Features
========

* Parses ASN.1 notation file
* Generates sturcts/classes based upon a notation file
* Encodes to BER


There is a still a lot of work to do to make this into a fully fledge ASN.1 library.

Not all types are supported as of now. Its limited to whats required to use ldap.

Decoding has not yet been started. Until encoding is done there is little point doing it.


Examples
-------

Mixin a generated sturct/classes from a notation file.
```D
mixin ASN1StructureFile!"ldap.asn";
```

It will be expanded into a global struct (e.g. Lightweight_Directory_Access_Protocol_V3) that contains all the items under it.

This allows mixing in multiple ASN.1 notation files per module.
