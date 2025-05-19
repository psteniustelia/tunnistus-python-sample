# Get entity statement

## First time - validate with fingerprint

    python update-entity-statement.py -u https://tunnistus-pp.telia.fi/.well-known/openid-federation --fingerprint 2bb459b631d4c157f91ef7858d7f5baec6961d1d59df1b61eff7ae6905061cda

## Subsequent updates - validate with previous entity statement

    python update-entity-statement.py -u https://tunnistus-pp.telia.fi/.well-known/openid-federation --previous openid-federation.jwt

# Create registration request

    python registration-request.py 

# Launch server

    python client.py

