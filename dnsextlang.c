/*
 * dnsextlang.c -- generate type descriptors from dnsextlang stanzas
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

// https://datatracker.ietf.org/doc/html/draft-levine-dnsextlang-12

#define _GNU_SOURCE
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <limits.h>

#include "mustach.h"

extern char *readfile(const char *, size_t *);


typedef struct option option_t;
struct option {
  const char *name;
};

typedef struct qualifier qualifier_t;
struct qualifier {
  const char *name;
};

typedef struct symbol symbol_t;
struct symbol {
  char *name;
  uint32_t value;
};

typedef struct type type_t;
struct type {
  const char *name;
  struct { size_t size; const qualifier_t **data; } qualifiers;
  struct { size_t size; symbol_t *data; } symbols;
};

typedef struct {
  type_t *type;
  char *name;
  char *freetext;
} field_t;

typedef struct {
  char *name;
  uint32_t code;
  char *freetext;
  struct { size_t size; const option_t **data; } options;
  struct { size_t size; field_t *data; } fields;
} record_t;

typedef struct {
  size_t size;
  record_t *data;
} records_t;

static const option_t options[] = {
  { "X" }, // extra
  { "I" }, // in class
  { "A" }, // any class
  { "O" }, // obsolete
  { "E" }, // experimental
  { NULL }
};

// dummy, parse symbolic field values instead
static const qualifier_t I_quals[] = {
  { NULL }
};

static const qualifier_t N_quals[] = {
  { "C" }, // name is compressed
  { "A" }, // name represents a mailbox
  { "L" }, // name converted to lower case for DNSSEC validation
  { "O" }, // name is optional (can only appear as last field)
  { NULL }
};

static const qualifier_t S_quals[] = {
  { "M" }, // sequence
  { "X" }, // hex
  { NULL }
};

static const qualifier_t X_quals[] = {
  { "C" }, // stored as string
  { NULL }
};

static const qualifier_t T_quals[] = {
  { "L" }, // ttl (extension hopefully included in the draft)
  { NULL }
};

static const qualifier_t Z_quals[] = {
  { "WKS" },
  { "NSAP" },
  { "NXT" },
  { "A6P" },
  { "A6S" },
  { "APL" },
  { "IPSECKEY" },
  { "HIPHIT" },
  { "HIPPK" },
  { "SVCB" },
  { NULL }
};

static const qualifier_t R_quals[] = {
  { "L" }, // nsec
  { NULL }
};

// field types as defined in section 3.1 (R mentioned in section 3.5.1)
static const struct {
  const char *name;
  const qualifier_t *qualifiers;
} types[] = {
  { "I1",   I_quals },
  { "I2",   I_quals },
  { "I4",   I_quals },
  { "A",    0       },
  { "AAAA", 0       },
  { "N",    N_quals },
  { "S",    S_quals },
  { "B32",  0       },
  { "B64",  0       },
  { "X",    X_quals },
  { "T",    T_quals },
  { "Z",    Z_quals },
  { "R",    R_quals }
};

#define BAD_RECORD (-1)
#define BAD_FIELD (-2)
#define NO_MEMORY (-3)
#define BAD_RANGE (-4)

static int parse_symbols(type_t *type, char *str)
{
  size_t cnt;
  char *saveptr = NULL, *tok;

  cnt = 1;
  for (char *ptr=str; *ptr; ptr++)
    if (*ptr == ',')
      cnt++;

  if (!(type->symbols.data = calloc(cnt, sizeof(*type->symbols.data))))
    return NO_MEMORY;
  type->symbols.size = cnt;

  cnt = 0;
  for (char *ptr=str; (tok=strtok_r(ptr, ",", &saveptr)); ptr=NULL) {
    size_t len = 0;
    for (; tok[len] && tok[len] != '='; len++)
      ;
    if (tok[len] != '=')
      return BAD_RECORD;
    char *end;
    unsigned long lng = strtoul(&tok[len+1], &end, 10);
    if (*end != '\0')
      return BAD_RECORD;
    if (!(type->symbols.data[cnt].name = strndup(tok, len)))
      return NO_MEMORY;
    type->symbols.data[cnt].value = (uint32_t)lng;
    cnt++;
  }

  assert(type->symbols.size <= cnt);

  return 0;
}

static int parse_qualifiers(type_t *type, const qualifier_t *quals, char *str)
{
  size_t cnt;
  char *saveptr = NULL, *tok;

  cnt = 1;
  for (char *ptr=str; *ptr; ptr++)
    if (*ptr == ',')
      cnt++;

  if (!(type->qualifiers.data = calloc(cnt, sizeof(*type->qualifiers.data))))
    return NO_MEMORY;
  type->qualifiers.size = cnt;

  cnt = 0;
  for (char *ptr=str; (tok=strtok_r(ptr, ",", &saveptr)); ptr=NULL) {
    const qualifier_t *qual = NULL;
    for (size_t i=0; quals[i].name; i++) {
      if (strcasecmp(tok, quals[i].name) != 0)
        continue;
      qual = &quals[i];
      break;
    }
    if (!qual)
      return BAD_RECORD;
    type->qualifiers.data[cnt++] = qual;
  }

  assert(type->qualifiers.size <= cnt);

  return 0;
}

static int parse_field(field_t *fld, char *str, size_t len)
{
  int type = -1;
  size_t cur = 0, end;
  const char *ftype, *name = "", *freetext;
  char *quals = NULL;

  (void)len;

  // drop any leading spaces
  for (; isspace(str[cur]); cur++)
    ;
  ftype = &str[cur];

  // skip ahead to qualifiers, name or freetext
  for (; str[cur] && str[cur] != ':' && str[cur] != '['; cur++)
    ;

  // qualifiers
  if (str[cur] == '[') {
    str[cur++] = '\0';
    quals = str + cur;
    for (; str[cur] && str[cur] != ']'; cur++)
      ;
    if (str[cur] != ']')
      return BAD_RECORD;
    str[cur++] = '\0';
  }

  // name
  if (str[cur] == ':') {
    str[cur++] = '\0';
    name = str + cur;
    for (; str[cur] && !isspace(str[cur]); cur++)
      ;
    if (isspace(str[cur]))
      str[cur++] = '\0';
  }

  // drop any spaces
  for (; isspace(str[cur]); cur++)
    ;
  // freetext
  freetext = &str[cur];
  // drop any trailing spaces
  end = cur;
  for (; str[cur]; cur++)
    if (!isspace(str[cur]))
      end = cur+1;
  str[end] = '\0';

  for (int i=0, n=sizeof(types)/sizeof(types[0]); i < n; i++) {
    if (strcasecmp(ftype, types[i].name) != 0)
      continue;
    type = i;
    break;
  }

  if (type < 0)
    return BAD_RECORD;
  if (!(fld->type = calloc(1, sizeof(*fld->type))))
    return NO_MEMORY;
  fld->type->name = types[type].name;
  if (name && !(fld->name = strdup(name)))
    return NO_MEMORY;
  if (freetext && !(fld->freetext = strdup(freetext)))
    return NO_MEMORY;

  if (!quals)
    return 0;
  else if (types[type].qualifiers == I_quals)
    return parse_symbols(fld->type, quals);
  else if (types[type].qualifiers)
    return parse_qualifiers(fld->type, types[type].qualifiers, quals);
  else
    return BAD_RECORD;
}

#define EXTRA (1u<<0)
#define IN (1u<<1)
#define ANY (1u<<2)
#define OBSOLETE (1u<<3)
#define EXPERIMENTAL (1u<<4)

static int parse_record(record_t *rec, char *str, size_t len)
{
  char *ptr = NULL;
  uint16_t type;
  uint32_t opts = 0, optcnt = 0;
  size_t cnt = 0, namelen = 0;
  const char *optstr = NULL;

  assert(len);

  if (!isalpha(str[cnt]))
    return BAD_RECORD;

  for (++cnt; cnt < len; cnt++) {
    if (isalnum(str[cnt]) || str[cnt] == '-')
      continue;
    if (str[cnt] == ':')
      break;
    return BAD_RECORD;
  }

  assert(str[cnt] == ':');
  namelen = cnt;

  unsigned long lng;
  if (!(lng = strtoul(&str[cnt+1], &ptr, 10)) || lng > UINT16_MAX)
    return BAD_RECORD;
  type = (uint16_t)lng;

  cnt = ptr - str;
  if (str[cnt] == ':') {
    optstr = &str[++cnt];
    for (; cnt < len; cnt++) {
      uint32_t opt;
      if (str[cnt] == 'X')
        opt = EXTRA;
      else if (str[cnt] == 'I')
        opt = IN;
      else if (str[cnt] == 'A')
        opt = ANY;
      else if (str[cnt] == 'O')
        opt = OBSOLETE;
      else if (str[cnt] == 'E')
        opt = EXPERIMENTAL;
      else if (isspace(str[cnt]) || str[cnt] == '\0')
        break;
      else
        return BAD_RECORD;
      optcnt += !(opts & opt);
      opts |= opt;
    }
    if (str[cnt] != '\0')
      str[cnt++] = '\0';
  }

  // drop any spaces
  for (; isspace(str[cnt]); cnt++)
    ;
  // freetext
  const char *freetext = &str[cnt];
  // drop any trailing spaces
  size_t end = cnt;
  for (; str[cnt]; cnt++)
    if (!isspace(str[cnt]))
      end = cnt+1;
  str[end] = '\0';

  if (!(rec->name = strndup(str, namelen)))
    return NO_MEMORY;
  if (!(rec->freetext = strdup(freetext)))
    return NO_MEMORY;
  rec->code = type;
  if (opts) {
    opts = 0;
    rec->options.size = 0;
    if (!(rec->options.data = calloc(optcnt, sizeof(*rec->options.data))))
      return NO_MEMORY;
    for (int i=0; optstr[i]; i++) {
      uint32_t opt = 0;
      if (optstr[i] == 'X')
        opt = EXTRA;
      else if (optstr[i] == 'I')
        opt = IN;
      else if (optstr[i] == 'A')
        opt = ANY;
      else if (optstr[i] == 'O')
        opt = OBSOLETE;
      else if (optstr[i] == 'E')
        opt = EXPERIMENTAL;
      else
        break;

      if (opts & opt) // ensure options do not appear more than once
        continue;

      for (int j=0; options[j].name; j++) {
        if (tolower((unsigned char)optstr[i]) != tolower((unsigned char)options[j].name[0]))
          continue;
        rec->options.data[rec->options.size++] = &options[j];
        break;
      }
    }

    assert(rec->options.size == optcnt);
  }
  return 0;
}

static ssize_t parse_records(records_t *recs, FILE *stream)
{
  int err = 0;
  char *str = NULL;
  size_t len = 0, line = 0;
  enum { INITIAL, RECORD } state = INITIAL;
  record_t *rec = NULL;

  while (getline(&str, &len, stream) != -1) {
    line++;

    // ignore leading whitespace
    char *ptr = str;
    while (*ptr && isspace(*ptr))
      ptr++;
    // discard lines where the first character is a '#'
    if (!*ptr || *ptr == '#')
      continue;

    switch (state) {
      case INITIAL: {
        record_t *data;
        const size_t size = (recs->size + 1) * sizeof(*data);
        if (!(data = realloc(recs->data, size)))
          goto no_memory;
        recs->size++;
        recs->data = data;
        rec = &data[recs->size - 1];
        memset(rec, 0, sizeof(*rec));
        if ((err = parse_record(rec, str, len)) < 0)
          goto error;
        state = RECORD;
      } break;
      case RECORD: {
        if (ptr != str) {
          assert(rec);

          field_t *data;
          const size_t size = (rec->fields.size + 1) * sizeof(*data);
          if (!(data = realloc(rec->fields.data, size)))
            goto no_memory;
          rec->fields.size++;
          rec->fields.data = data;
          memset(&data[rec->fields.size - 1], 0, sizeof(data[size - 1]));
          if ((err = parse_field(&data[rec->fields.size - 1], str, len)) < 0)
            goto error;
        } else {
          record_t *data;
          const size_t size = (recs->size + 1) * sizeof(*data);
          if (!(data = realloc(recs->data, size)))
            goto no_memory;
          recs->size++;
          recs->data = data;
          rec = &data[recs->size - 1];
          memset(rec, 0, sizeof(*rec));
          if ((err = parse_record(rec, str, len)) < 0)
            goto error;
        }
      } break;
    }
  }

  return 0;
no_memory:
  err = NO_MEMORY;
error:
  if (str)
    free(str);
  return err;
}

static char *upper(const char *s)
{
  char *p;
  if ((p = strdup(s)))
    for (char *q=p; *q; q++)
      *q = (unsigned char)toupper((unsigned char)*q);
  return p;
}

static char *lower(const char *s)
{
  char *p;
  if ((p = strdup(s)))
    for (char *q=p; *q; q++)
      *q = (unsigned char)tolower((unsigned char)*q);
  return p;
}

#define VOID (0u)
#define STRING (1u<<0)
#define INTEGER (1u<<1)
#define SCALAR (STRING|INTEGER)
#define OBJECT (1u<<2)

#define REFERENCE (1u<<3)
#define KEY (1u<<4)

//
// record(s)
//   - name
//   - code
//   - freetext
//   - options
//   - field(s)
//     - name
//     - freetext
//     - type
//       - qualifiers (non-integers only)
//         - name
//       - symbols (integers only)
//         - name
//         - code
//

// operators are supported for scalar values, i.e. {{key}}. not every operator
// can be used on a given value. e.g. a numeric value cannot be converted to
// upper/lower case. use dot (".") operator notation to use an operator. e.g.
// {{key.upper}} or {{.lower}} if the scope is the scalar value.

typedef struct operator operator_t;
struct operator {
  const char *name;
  char *(*function)(const char *);
};

typedef struct descriptor descriptor_t;
struct descriptor {
  const char *name;
  uint32_t type;
  union {
    struct {
      size_t size; // object size in bytes
      ssize_t count_offset; // offset of vector size, negative for singletons
      size_t base_offset; // offset of vector base address
      const descriptor_t *descriptors;
      // operators?
    } object;
    struct {
      size_t offset; // offset of member within object
      const operator_t *operators;
    } scalar;
  };
};

static const operator_t string_operators[] = {
  { "upper", upper },
  { "lower", lower },
  { NULL, 0 }
};

static const descriptor_t qualifier_descriptor[] = {
  { "name", STRING | KEY, {
    .scalar = { offsetof(qualifier_t, name), string_operators } } },
  { NULL, 0, { .scalar = { 0 } } }
};

static const descriptor_t symbol_descriptor[] = {
  { "name", STRING | KEY, {
    .scalar = { offsetof(symbol_t, name), string_operators } } },
  { "value", INTEGER | KEY, {
    .scalar = { offsetof(symbol_t, value), NULL } } },
  { NULL, 0, { .scalar = { 0, NULL } } }
};

static const descriptor_t type_descriptor[] = {
  { "name", STRING | REFERENCE | KEY, {
    .scalar = { offsetof(type_t, name), string_operators } } },
  { "qualifiers", OBJECT | REFERENCE, {
    .object = {
      sizeof(qualifier_t),
      offsetof(type_t, qualifiers.size), 
      offsetof(type_t, qualifiers.data),
      qualifier_descriptor } } },
  { "symbols", OBJECT, {
    .object = {
      sizeof(symbol_t),
      offsetof(type_t, symbols.size),
      offsetof(type_t, symbols.data),
      symbol_descriptor } } },
  { NULL, 0, { .scalar = { 0, NULL } } }
};

static const descriptor_t field_descriptor[] = {
  { "name", STRING | KEY, {
    .scalar = { offsetof(field_t, name), string_operators } } },
  { "freetext", STRING, {
    .scalar = { offsetof(field_t, freetext), string_operators } } },
  { "type", OBJECT, {
    .object = {
      sizeof(type_t),
      -1,
      offsetof(field_t, type),
      type_descriptor } } },
  { NULL, 0, { .scalar = { 0, NULL } } }
};

static const descriptor_t option_descriptor[] = {
  { "name", STRING | KEY, {
    .scalar = { offsetof(option_t, name), string_operators } } },
  { NULL, 0, { .scalar = { 0, NULL } } }
};

static const descriptor_t record_descriptor[] = {
  { "name", STRING | KEY, {
    .scalar = { offsetof(record_t, name), string_operators } } },
  { "freetext", STRING, {
    .scalar = { offsetof(record_t, freetext), string_operators } } },
  { "code", INTEGER | KEY, { .scalar = { offsetof(record_t, code) } } },
  { "options", OBJECT | REFERENCE, {
     .object = {
       sizeof(option_t),
       offsetof(record_t, options.size),
       offsetof(record_t, options.data),
       option_descriptor } } },
  { "fields", OBJECT, {
    .object = {
      sizeof(field_t),
      offsetof(record_t, fields.size),
      offsetof(record_t, fields.data),
      field_descriptor } } },
  { NULL, 0, { .scalar = { 0, NULL } } }
};

typedef enum {
  DESCENDING = -1,
  UNSORTED = 0,
  ASCENDING = 1
} order_t;

#define LEXICAL (STRING)
#define NUMERICAL (INTEGER)

typedef struct clause clause_t;
struct clause {
  uint32_t type;
  order_t order;
  union {
    struct {
      bool pad;
      uint64_t from, to;
    } numerical;
    struct {
      char from[32], to[32];
    } lexical;
  };
};

#define IGNORE ((uint64_t)UINT32_MAX + 2)
#define WILDCARD ((uint64_t)UINT32_MAX + 1)

typedef struct selector selector_t;
struct selector {
  uint32_t type;
  order_t order;
  struct {
    clause_t *base;
    size_t count, cursor;
  } clauses;
  struct {
    void **base;
    size_t count, cursor;
  } objects;
  const descriptor_t *key;
  void *dummy;
  void *object;
  uint32_t code;
};

static inline int parse_numerical_clause(
  clause_t *clause, const char *from, const char *to, uint32_t type, order_t order)
{
  unsigned long number;
  char *end = NULL;

  if (type && type != INTEGER)
    return BAD_RANGE;

  clause->type = INTEGER;

  if (strcmp(from, "*") == 0)
    clause->numerical.from = WILDCARD;
  else if ((number = strtoul(from, &end, 10)) > UINT16_MAX || *end)
    return BAD_RANGE;
  else
    clause->numerical.from = (uint32_t)number;

  if (!*to)
    clause->numerical.to = IGNORE;
  else if (strcmp(to, "*") == 0)
    clause->numerical.to = WILDCARD;
  else if ((number = strtoul(to, &end, 10)) > UINT16_MAX || *end)
    return BAD_RANGE;
  else
    clause->numerical.to = (uint32_t)number;

  if (clause->numerical.from > clause->numerical.to)
    clause->order = DESCENDING;
  else
    clause->order = ASCENDING;

  if (!order || clause->order == order)
    return 0;
  assert(clause->numerical.to != IGNORE);
  uint64_t temp = clause->numerical.from;
  clause->numerical.from = clause->numerical.to;
  clause->numerical.to = temp;
  clause->order = order;
  return 0;
}

static inline int parse_lexical_clause(
  clause_t *clause, const char *from, const char *to, uint32_t type, order_t order)
{
  if (type && type != STRING)
    return BAD_RANGE;

  clause->type = STRING;
  clause->order = UNSORTED;

  if (strcmp(from, "*") == 0) {
    clause->order = DESCENDING;
  } else if (isalpha(*from)) {
    for (size_t i=1; from[i]; i++)
      if (!isalnum((unsigned char)from[i]))
        return BAD_RANGE;
  } else {
    return BAD_RANGE;
  }

  if (strcmp(to, "*") == 0) {
    clause->order = ASCENDING;
  } else if (isalpha(*to)) {
    for (size_t i=1; to[i]; i++)
      if (!isalnum((unsigned char)to[i]))
        return BAD_RANGE;
  } else if (!*to) {
    clause->order = ASCENDING;
  } else {
    return BAD_RANGE;
  }

  snprintf(clause->lexical.from, sizeof(clause->lexical.from), "%s", from);
  snprintf(clause->lexical.to, sizeof(clause->lexical.to), "%s", to);

  if (!clause->order)
    clause->order = strcmp(from, to) < 0 ? DESCENDING : ASCENDING;
  if (!order || clause->order == order)
    return 0;

  char temp[32];
  memcpy(temp, clause->lexical.from, sizeof(temp));
  memcpy(clause->lexical.from, clause->lexical.to, sizeof(temp));
  memcpy(clause->lexical.to, temp, sizeof(temp));
  clause->order = order;
  return 0;
}

static int parse_clause(
  clause_t *clause, char *expression, uint32_t type, order_t order)
{
  char *from = expression, *operator = expression, *to = expression;

  if (!expression)
    return BAD_RANGE;

  for (; isalnum((unsigned char)*operator) || *operator == '*'; operator++)
    ;

  if (strncmp(operator, "-", 1) == 0)
    to = operator + 1;
  else if (strncmp(operator, "..", 2) == 0)
    to = operator + 2;
  else if (!*operator)
    to = operator;
  else
    return BAD_RANGE;

  *operator = '\0';
  clause->numerical.pad = (to - operator) > 1;

  if (!*from)
    return BAD_RANGE;
  if (!*to && *operator)
    return BAD_RANGE;

  if (strcmp(from, "*") == 0 && strcmp(to, "*") == 0)
    return BAD_RANGE;
  else if (isdigit(*from) || isdigit(*to))
    return parse_numerical_clause(clause, from, to, type, order);
  else if (clause->numerical.pad)
    return BAD_RANGE;
  else
    return parse_lexical_clause(clause, from, to, type, order);
}

static int parse_clauses(selector_t *selector, const char *expression)
{
  size_t count = 0;
  int32_t result = 0;

  assert(selector);
  assert(!selector->clauses.base);

  selector->type = VOID;
  selector->order = UNSORTED;
  selector->clauses.count = 0;
  selector->clauses.base = NULL;

  if (!expression)
    return 0;
  expression += *expression == '[';
  size_t length = strcspn(expression, "]");

  char *token, *tokens, *filter;
  if (!(filter = strndup(expression, length)))
    goto no_memory;
  count = 0;
  tokens = filter;
  while ((token = strsep(&tokens, ",")) && *token)
    count++;
  free(filter);
  filter = NULL;

  if (!count)
    return 0;

  if (!(selector->clauses.base = calloc(count, sizeof(clause_t))))
    goto no_memory;
  if (!(filter = strndup(expression, length)))
    goto no_memory;
  tokens = filter;
  token = strsep(&tokens, ",");
  assert(token);
  clause_t *clause = &selector->clauses.base[selector->clauses.count++];
  if ((result = parse_clause(clause, token, 0, 0)))
    goto bad_range;
  selector->type = clause->type;
  selector->order = clause->order;
  while ((token = strsep(&tokens, ",")) && *token) {
    clause = &selector->clauses.base[selector->clauses.count++];
    if ((result = parse_clause(clause, token, selector->type, selector->order)))
      goto bad_range;
  }
  free(filter);

  return 0;
no_memory:
  result = NO_MEMORY;
bad_range:
  if (filter)
    free(filter);
  return result;
}

static bool in_lexical_range(selector_t *selector, const char *name)
{
  while (selector->clauses.cursor < selector->clauses.count) {
    int result = 0;
    const clause_t *clause = &selector->clauses.base[selector->clauses.cursor];

    if (strcmp(clause->lexical.from, "*") == 0)
      goto wildcard;

    result = strcasecmp(name, clause->lexical.from);
    result *= selector->order;

    if (result < 0)
      return false;
    if (result == 0)
      return true;
wildcard:
    if (result == 0 && strcasecmp(clause->lexical.to, "") == 0)
      return true;
    else if (strcasecmp(clause->lexical.to, "*") == 0)
      return true;

    result = strcasecmp(name, clause->lexical.to);
    result *= selector->order;

    if (result < 0 + (selector->order == DESCENDING))
      return true;
    selector->clauses.cursor++;
  }

  return false;
}

static const void *select_next_lexical(selector_t *selector)
{
  assert(!selector->code);

  const descriptor_t *descriptor = selector->key;
  assert(descriptor->type & KEY);
  assert(descriptor->type & SCALAR);
  while (selector->objects.cursor < selector->objects.count - 1) {
    const char *object = selector->objects.base[++selector->objects.cursor];
    const char *name = *(char**)(object + descriptor->scalar.offset);
    if (in_lexical_range(selector, name))
      return object;
  }

  return NULL;
}

static bool in_numerical_range(selector_t *selector, size_t code)
{
  while (selector->clauses.cursor < selector->clauses.count) {
    int result = 0;
    const clause_t *clause = &selector->clauses.base[selector->clauses.cursor];

    if (clause->numerical.from == WILDCARD)
      goto wildcard;
    else if (code < clause->numerical.from)
      result = -1;
    else if (code > clause->numerical.from)
      result = 1;

    result *= selector->order;

    if (result < 0)
      return false;
    if (result == 0)
      return true;
wildcard:
    if (result == 0 && clause->numerical.to == IGNORE)
      return true;
    else if (clause->numerical.to == WILDCARD)
      return true;
    else if (clause->numerical.to == IGNORE)
      result = 1;
    else if (code < clause->numerical.to)
      result = -1;
    else if (code > clause->numerical.to)
      result = 1;
    else
      result = 0;

    result *= selector->order;

    if (result < 0 + (selector->order == DESCENDING))
      return true;
    selector->clauses.cursor++;
  }

  return false;
}

static const void *select_next_numerical(selector_t *selector)
{
  assert(!selector->code);

  const descriptor_t *descriptor = selector->key;
  while (selector->objects.cursor < selector->objects.count - 1) {
    const char *object = selector->objects.base[++selector->objects.cursor];
    uint32_t code = *(uint32_t*)(object + descriptor->scalar.offset);
    if (in_numerical_range(selector, code))
      return object;
  }

  return NULL;
}

static const void *select_next(selector_t *selector)
{
  assert(selector);

  if (!selector->objects.base)
    return NULL;
  if (!selector->clauses.base && selector->objects.cursor == selector->objects.count)
    return NULL;
  if (!selector->clauses.base)
    return selector->objects.base[selector->objects.cursor++];
  if (selector->clauses.cursor == selector->clauses.count)
    return NULL;

  const clause_t *clause = &selector->clauses.base[selector->clauses.cursor];

  if (clause->type == LEXICAL)
    return select_next_lexical(selector);
  if (clause->type == NUMERICAL && !clause->numerical.pad)
    return select_next_numerical(selector);

  const descriptor_t *descriptor = selector->key;

  assert(clause->type == NUMERICAL);
  for (;;) {
    if (selector->clauses.cursor == selector->clauses.count)
      break;
    if (selector->order == DESCENDING && !selector->code)
      break;
    else if (selector->order == DESCENDING)
      selector->code--;
    else
      selector->code++;

    if (!in_numerical_range(selector, selector->code))
      continue;

    while (selector->objects.cursor < selector->objects.count) {
      const char *object = selector->objects.base[selector->objects.cursor];
      uint32_t code = *(uint32_t *)(object + descriptor->scalar.offset);
      if (selector->order == ASCENDING && code > selector->code)
        break;
      if (selector->order == DESCENDING && code < selector->code)
        break;
      if (code == selector->code)
        return (void*)object;
      selector->objects.cursor++;
    }

    *(uint32_t *)(selector->dummy+descriptor->scalar.offset) = selector->code;
    return selector->dummy;
  }

  return NULL;
}

static const void *select_first_lexical(selector_t *selector)
{
  assert(!selector->code);

  const descriptor_t *descriptor = selector->key;
  if (selector->objects.cursor < selector->objects.count) {
    const char *object = selector->objects.base[selector->objects.cursor];
    const char *name = *(char**)(object + descriptor->scalar.offset);
    if (in_lexical_range(selector, name))
      return object;
    return select_next_lexical(selector);
  }

  return NULL;
}

static const void *select_first_numerical(selector_t *selector)
{
  assert(!selector->code);

  const descriptor_t *descriptor = selector->key;
  if (selector->objects.cursor < selector->objects.count) {
    const char *object = selector->objects.base[selector->objects.cursor];
    uint32_t code = *(uint32_t*)(object + descriptor->scalar.offset);
    if (in_numerical_range(selector, code))
      return object;
    return select_next_numerical(selector);
  }

  return NULL;
}

static const void *select_first(selector_t *selector)
{
  selector->code = 0;
  selector->objects.cursor = 0;
  selector->clauses.cursor = 0;

  if (!selector->objects.base)
    return NULL;
  assert(selector->objects.count > 0);
  if (!selector->clauses.base)
    return selector->objects.base[selector->objects.cursor++];
  if (selector->clauses.cursor == selector->clauses.count)
    return NULL;

  const clause_t *clause = &selector->clauses.base[selector->clauses.cursor];

  if (clause->type == LEXICAL)
    return select_first_lexical(selector);
  if (clause->type == NUMERICAL && !clause->numerical.pad)
    return select_first_numerical(selector);

  const descriptor_t *descriptor = selector->key;
  assert(clause->type == NUMERICAL);
  if (clause->order == DESCENDING && clause->numerical.from >= WILDCARD) {
    const char *object = selector->objects.base[selector->objects.cursor];
    selector->code = *(uint32_t *)(object + descriptor->scalar.offset);
  } else {
    selector->code = clause->numerical.from;
  }

  if (!in_numerical_range(selector, selector->code))
    return select_next(selector);

  while (selector->objects.cursor < selector->objects.count) {
    const char *object = selector->objects.base[selector->objects.cursor];
    uint32_t code = *(uint32_t *)(object + descriptor->scalar.offset);
    if (code > selector->code)
      break;
    if (code == selector->code)
      return (void *)object;
    selector->objects.cursor++;
  }

  char *object = selector->dummy;
  *(uint32_t*)(object + descriptor->scalar.offset) = selector->code;
  return selector->dummy;
}

typedef struct scope scope_t;
struct scope {
  const void *object;
  const descriptor_t *descriptor;
  selector_t selector;
};

typedef struct stack stack_t;
struct stack {
  scope_t scopes[10u];
  uint32_t depth;
};

static int compare(const void *p1, const void *p2, void *arg)
{
  const char *o1 = *(void**)p1, *o2 = *(void**)p2;
  const selector_t *selector = arg;

  assert(selector);
  assert(selector->order);

  if (selector->type == NUMERICAL) {
    const uint32_t i1 = *(uint32_t*)&o1[selector->key->scalar.offset];
    const uint32_t i2 = *(uint32_t*)&o2[selector->key->scalar.offset];
    return selector->order * (i1 < i2 ? -1 : (i1 > i2 ? 1 : 0));
  } else {
    assert(selector->type == LEXICAL);
    const char *s1 = *(char **)&o1[selector->key->scalar.offset];
    const char *s2 = *(char **)&o2[selector->key->scalar.offset];
    int cmp = strcasecmp(s1, s2);
    return selector->order * (cmp < 0 ? -1 : (cmp > 0 ? 1 : 0));
  }
}

static int get_scalar(
  const void *object,
  const descriptor_t *descriptor,
  const char *name,
  struct mustach_sbuf *sbuf)
{
  assert(object);
  assert(descriptor && (descriptor->type & SCALAR));

  const char *operation = name;
  for (; *operation && isalnum((unsigned char)*operation); operation++)
    ; // skip ahead to operation
  operation += *operation == '.';

  char *(*function)(const char *) = 0;
  const operator_t *operator = descriptor->scalar.operators;
  for (; !function && operator && operator->name; operator++)
    if (strcasecmp(operation, operator->name) == 0)
      function = operator->function;

  if (*operation && !function)
    return MUSTACH_ERROR_UNDEFINED_TAG;
  if (!function)
    function = strdup;

  char number[32];
  const char *value = number;
  const size_t offset = descriptor->scalar.offset;
  if (descriptor->type & INTEGER)
    snprintf(number, sizeof(number), "%"PRIu32, *(uint32_t*)(object + offset));
  else
    value = *(const char **)(object + offset);

  if (!(sbuf->value = function(value)))
    return MUSTACH_ERROR_SYSTEM;
  sbuf->freecb = free;
  return MUSTACH_OK;
}

static int get(void *closure, const char *name, struct mustach_sbuf *sbuf)
{
  stack_t *stack = closure;
  assert(stack);
  assert(stack->depth > 0);
  const scope_t *scope = &stack->scopes[stack->depth - 1];
  const descriptor_t *descriptor = scope->descriptor;

  if (*name == '.' && !(descriptor->type & SCALAR))
    return get_scalar(scope->object, scope->selector.key, name, sbuf);
  if (*name == '.')
    return get_scalar(scope->object, scope->descriptor, name, sbuf);
  if (!(descriptor->type & OBJECT))
    return MUSTACH_ERROR_UNDEFINED_TAG;

  const char *selection = name;
  for (; *selection && isalnum((unsigned char)*selection); selection++)
    ; // find operation/selection or terminating null

  descriptor = descriptor->object.descriptors;
  for (; descriptor->name; descriptor++)
    if (strncasecmp(name, descriptor->name, selection - name) == 0)
      break;

  if (descriptor->type & SCALAR)
    return get_scalar(scope->object, descriptor, name, sbuf);

  // FIXME: implement support for get(ting) selections to return the number
  //        of elements in a set (by default, other operations may be
  //        implemented in the future).

  return MUSTACH_ERROR_UNDEFINED_TAG;
}

static const char *skip_operation(const char *s)
{
  while (*s) s++;
  return s;
}

static const char *skip_selection(const char *s)
{
  while (*s && *s != ']') s++;
  return s + (*s == ']');
}

static int enter(void *closure, const char *name)
{
  stack_t *stack = closure;
  scope_t *scope = &stack->scopes[stack->depth - 1];

  // selections are expressed between curly brackets ("{" and "}"). selections
  // can be used to limit (or pad) and order sets, e.g. {{records{a-*}}} or
  // {{type{i1,i2,i3}}}. operations are expressed by suffixing the key by a
  // dot (".") and the operation, e.g. {{name.upper}} or {{symbols.count}}.
  // selections and operations can be mixed, e.g. {{records{a-*}.count}}.

  const descriptor_t *descriptor = scope->descriptor;
  if (descriptor->type & SCALAR) // scalars have no members
    return MUSTACH_ERROR_UNDEFINED_TAG;

  const char *expression = name;
  for (; *expression && isalnum((unsigned char)*expression); expression++)
    ; // find selection/operation or terminating null

  descriptor = scope->descriptor->object.descriptors;
  for (; descriptor->name; descriptor++)
    if (strncasecmp(name, descriptor->name, expression - name) == 0)
      break;

  if (!descriptor->type)
    return MUSTACH_ERROR_UNDEFINED_TAG;

  const char *selection = expression, *operation = expression;
  if (*expression == '.')
    selection = skip_operation(operation);
  else if (*expression == '[')
    operation = skip_selection(selection);
  else if (*expression) // invalid selection or operation
    return MUSTACH_ERROR_UNDEFINED_TAG;

  assert(selection && operation);

  // operations not allowed for enter
  if (*operation)
    return MUSTACH_ERROR_UNDEFINED_TAG;
  // selections not allowed for scalars
  if (*selection && (descriptor->type & SCALAR))
    return MUSTACH_ERROR_UNDEFINED_TAG;


  size_t offset;
  if (descriptor->type & SCALAR)
    offset = descriptor->scalar.offset;
  else
    offset = descriptor->object.base_offset;

  const char *object = scope->object;
  if ((descriptor->type & STRING) && !*(char**)(object + offset))
    return 0;
  scope = &stack->scopes[stack->depth++];
  if ((descriptor->type & SCALAR))
    scope->object = object;
  else
    scope->object = *(void**)(object + offset);
  scope->descriptor = descriptor;
  memset(&scope->selector, 0, sizeof(scope->selector));
  if (descriptor->type & SCALAR)
    return 1;

  int error;
  selector_t *selector = &scope->selector;
  if ((error = parse_clauses(selector, selection)))
    return error;

  const descriptor_t *key;
  const uint32_t mask = KEY | selector->type;
  for (key = descriptor->object.descriptors; key->type; key++)
    if ((key->type & mask) == mask)
      break;

  if (selector->order && !key->type)
    return MUSTACH_ERROR_UNDEFINED_TAG;

  selector->key = key;
  selector->objects.count = 1;
  if (descriptor->object.count_offset >= 0)
    selector->objects.count = *(uint32_t*)(object + descriptor->object.count_offset);
  if (selector->objects.count == 0)
    goto empty;
  if (!(selector->dummy = malloc(descriptor->object.size)))
    return MUSTACH_ERROR_SYSTEM;
  memset(selector->dummy, 0, descriptor->object.size);
  if (!(selector->objects.base = calloc(selector->objects.count, sizeof(void*))))
    return MUSTACH_ERROR_SYSTEM;
  if (descriptor->type & REFERENCE)
    for (size_t i=0; i < selector->objects.count; i++)
      selector->objects.base[i] = *(void**)&scope->object[i * sizeof(void*)];
  else
    for (size_t i=0; i < selector->objects.count; i++)
      selector->objects.base[i] = (void*)&scope->object[i * descriptor->object.size];

  if (selector->order)
    qsort_r(selector->objects.base,
            selector->objects.count,
            sizeof(void*),
            compare, selector);

  if ((scope->object = select_first(&scope->selector)))
    return 1;

empty:
  if (selector->clauses.base)
    free(selector->clauses.base);
  free(selector->objects.base);
  free(selector->dummy);
  stack->depth--;
  return 0;
}

static int next(void *closure)
{
  stack_t *stack = closure;
  scope_t *scope = &stack->scopes[stack->depth - 1];
  if (scope->descriptor->type & SCALAR)
    return 0;
  scope->object = select_next(&scope->selector);
  return scope->object != NULL;
}

static int leave(void *closure)
{
  stack_t *stack = closure;
  scope_t *scope = &stack->scopes[--stack->depth];
  if (scope->descriptor->type & SCALAR)
    return MUSTACH_OK;
  if (scope->selector.clauses.base)
    free(scope->selector.clauses.base);
  free(scope->selector.objects.base);
  free(scope->selector.dummy);
  return MUSTACH_OK;
}

static void usage(const char *program)
{
  fprintf(stderr, "Usage: %s [OPTIONS] STANZAS TEMPLATE\n", program);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
  records_t records = { 0, NULL };
  struct mustach_itf itf = { 0, 0, &enter, &next, &leave, 0, 0, &get, 0 };

  FILE *input = NULL;
  const char *stanzas_file;
  const char *template_file;

  if (argc != 3)
    usage(argv[0]);

  stanzas_file = argv[1];
  template_file = argv[2];

  if (!(input = fopen(stanzas_file, "rb"))) {
    fprintf(stderr, "Cannot open %s for reading\n", stanzas_file);
    exit(EXIT_FAILURE);
  }

  char *template = readfile(template_file, 0);

  if (parse_records(&records, input) < 0) {
    fprintf(stderr, "Big fat error!\n");
    exit(EXIT_FAILURE);
  }

  const struct wrap {
    const char *version;
    records_t records;
  } wrap = {
    "0.1.0", // generated eventually
    { records.size, records.data }
  };

  const descriptor_t wrap_descriptor[] = {
    { "records", OBJECT, {
      .object = {
        sizeof(record_t),
        offsetof(struct wrap, records.size),
        offsetof(struct wrap, records.data),
        record_descriptor } } },
    { NULL, 0, { .scalar = { 0, NULL } } }
  };

  const descriptor_t descriptor = {
    NULL, OBJECT, {
      .object = {
        sizeof(wrap),
        -1,
        0,
        wrap_descriptor } },
  };

  stack_t stack = { 0 };
  scope_t *scope = &stack.scopes[stack.depth++];
  scope->object = &wrap;
  scope->descriptor = &descriptor;

  mustach_file(template, 0, &itf, &stack, 0, stdout);

  fclose(input);
  return 0;
}
