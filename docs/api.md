# csrbuilder API Documentation

### `pem_armor_csr()` function

> ```python
> def pem_armor_csr(certification_request):
>     """
>     :param certification_request:
>         An asn1crypto.csr.CertificationRequest object of the CSR to armor.
>         Typically this is obtained from CSRBuilder.build().
>
>     :return:
>         A byte string of the PEM-encoded CSR
>     """
> ```
>
> Encodes a CSR into PEM format

### `CSRBuilder()` class

> ##### constructor
>
> > ```python
> > def __init__(self, subject, subject_public_key):
> >     """
> >     :param subject:
> >         An asn1crypto.x509.Name object, or a dict - see the docstring
> >         for .subject for a list of valid options
> >
> >     :param subject_public_key:
> >         An asn1crypto.keys.PublicKeyInfo object containing the public key
> >         the certificate is being requested for
> >     """
> > ```
> >
> > Unless changed, CSRs will use SHA-256 for the signature
>
> ##### `.subject` attribute
>
> > An asn1crypto.x509.Name object, or a dict with at least the
> > following keys:
> >
> >  - country_name
> >  - state_or_province_name
> >  - locality_name
> >  - organization_name
> >  - common_name
> >
> > Less common keys include:
> >
> >  - organizational_unit_name
> >  - email_address
> >  - street_address
> >  - postal_code
> >  - business_category
> >  - incorporation_locality
> >  - incorporation_state_or_province
> >  - incorporation_country
> >
> > Uncommon keys include:
> >
> >  - surname
> >  - title
> >  - serial_number
> >  - name
> >  - given_name
> >  - initials
> >  - generation_qualifier
> >  - dn_qualifier
> >  - pseudonym
> >  - domain_component
> >
> > All values should be unicode strings
>
> ##### `.subject_public_key` attribute
>
> > An asn1crypto.keys.PublicKeyInfo or oscrypto.asymmetric.PublicKey
> > object of the subject's public key.
>
> ##### `.hash_algo` attribute
>
> > A unicode string of the hash algorithm to use when signing the
> > request - "sha1" (not recommended), "sha256" or "sha512"
>
> ##### `.ca` attribute
>
> > None or a bool - if the request is for a CA cert. None indicates no
> > basic constraints extension request.
>
> ##### `.subject_alt_domains` attribute
>
> > A list of unicode strings of all domains in the subject alt name
> > extension request. Empty list indicates no subject alt name extension
> > request.
>
> ##### `.subject_alt_ips` attribute
>
> > A list of unicode strings of all IPs in the subject alt name extension
> > request. Empty list indicates no subject alt name extension request.
>
> ##### `.key_usage` attribute
>
> > A set of unicode strings representing the allowed usage of the key.
> > Empty set indicates no key usage extension request.
>
> ##### `.extended_key_usage` attribute
>
> > A set of unicode strings representing the allowed usage of the key from
> > the extended key usage extension. Empty set indicates no extended key
> > usage extension request.
>
> ##### `.set_extension()` method
>
> > ```python
> > def set_extension(self, name, value):
> >     """
> >     :param name:
> >         A unicode string of an extension id name from
> >         asn1crypto.x509.ExtensionId
> >
> >     :param value:
> >         A value object per the specs defined by asn1crypto.x509.Extension
> >     """
> > ```
> >
> > Sets the value for an extension using a fully constructed Asn1Value
> > object from asn1crypto. Normally this should not be needed, and the
> > convenience attributes should be sufficient.
> >
> > See the definition of asn1crypto.x509.Extension to determine the
> > appropriate object type for a given extension. Extensions are marked
> > as critical when RFC5280 or RFC6960 indicate so. If an extension is
> > validly marked as critical or not (such as certificate policies and
> > extended key usage), this class will mark it as non-critical.
>
> ##### `.build()` method
>
> > ```python
> > def build(self, signing_private_key):
> >     """
> >     :param signing_private_key:
> >         An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
> >         object for the private key to sign the request with. This should be
> >         the private key that matches the public key.
> >
> >     :return:
> >         An asn1crypto.csr.CertificationRequest object of the request
> >     """
> > ```
> >
> > Validates the certificate information, constructs an X.509 certificate
> > and then signs it
