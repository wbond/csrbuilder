# csrbuilder Documentation

*csrbuilder* is a Python library for constructing CSRs - certificate signing
requests. It provides a high-level interface with knowledge of RFC 2986 to
produce, valid, correct requests without terrible APIs or hunting through RFCs.

Since its only dependencies are the
[*asn1crypto*](https://github.com/wbond/asn1crypto#readme) and
[*oscrypto*](https://github.com/wbond/oscrypto#readme) libraries, it is
easy to install and use on Windows, OS X, Linux and the BSDs.

The documentation consists of the following topics:

 - [Basic Usage](#basic-usage)
 - [API Documentation](api.md)

## Basic Usage

A simple, self-signed certificate can be created by generating a public/private
key pair using *oscrypto* and then passing a dictionary of name information to
the `CSRBuilder()` constructor:

```python
from oscrypto import asymmetric
from csrbuilder import CSRBuilder, pem_armor_csr


public_key, private_key = asymmetric.generate_pair('rsa', bit_size=2048)

with open('/path/to/my/env/will_bond.key', 'wb') as f:
    f.write(asymmetric.dump_private_key(private_key, 'password'))

builder = CSRBuilder(
    {
        'country_name': 'US',
        'state_or_province_name': 'Massachusetts',
        'locality_name': 'Newbury',
        'organization_name': 'Codex Non Sufficit LC',
        'common_name': 'Will Bond',
    },
    public_key
)
# Add subjectAltName domains
builder.subject_alt_domains = ['codexns.io', 'codexns.com']
request = builder.build(private_key)

with open('/path/to/my/env/will_bond.csr', 'wb') as f:
    f.write(pem_armor_csr(request))
```

All name components must be unicode strings. Common name keys include:

 - `country_name`
 - `state_or_province_name`
 - `locality_name`
 - `organization_name`
 - `common_name`

Less common keys include:

 - `organizational_unit_name`
 - `email_address`
 - `street_address`
 - `postal_code`
 - `business_category`
 - `incorporation_locality`
 - `incorporation_state_or_province`
 - `incorporation_country`

See [`CSRBuilder.subject`](api.md#subject-attribute) for a full
list of supported name keys.
