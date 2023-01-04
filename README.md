# Template renderer for dnsextlang stanzas

Simple proof of concept of [mustache][1] renderer for [dnsextlang][2] stanzas
built on [mustach][3].

The template language is mostly just mustach, but does add selectors for
filtering and ordering and a couple of simple scalar operators.

Based on the type of field you can either use lexical, numerical or padded
numerical selectors. i.e. `{{#records[a-*]}}`, `{{#records[0-*]}}` or
`{{#records[0..255]}}`. The order can be reversed using e.g.
`{{#records[*-a]}}`. Selectors also allow the user to make very detailed
selections. i.e. `{{#records[a,aaaa]}}` or `{{#type[i1,i2,i4}}`. mustache
allows for inverted sections through e.g. `{{^type[i1,i2,i4]}}` to render the
content if a field type is not an integer. Supplying no selectors will render
the set in the order it was specified in the dnsextlang stanza file.

Simple operators allow for altering the value of a key while rendering. For
now only `.upper` and `.lower` string operations are implemented.

To generate defines for all record types defined in a stanza file:
```
{{#records}}
#define XXX_{{name.upper}} ({{code}})
{{/records}}
```

For more complex rendering operations, like a descriptor table for a parser
where the descriptor must be accessible by it's type code:
```
{{#records[0..255]}}
{{#name}}
contents that renders name in upper case for codes with an associated name.
aka existing records.
{{.upper}}
{{/name}}
{{^name}}
contents that renders for codes with no associated name.
aka non-existing records.
{{/name}}
{{/records[0..255]}}
```

Each scope provides access to scalars and sets in that particular scope.

```
record(s)
  - name
  - code
  - freetext
  - options
    - name
  - field(s)
    - name
    - freetext
    - type
      - qualifiers (non-integers only)
        - name
      - symbols (integers only)
        - name
        - code
```

[1]: https://mustache.github.io/
[2]: https://datatracker.ietf.org/doc/html/draft-levine-dnsextlang-12
[3]: https://gitlab.com/jobol/mustach
