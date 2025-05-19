# Create registration request

    python registration-request.py --new

# Get entity statement

## First time - validate with fingerprint

    python update-entity-statement.py -u https://tunnistus-te.telia.fi/.well-known/openid-federation --fingerprint 5a63af389f778fd8e94572b8b84880caea22dc23da388d46fc3379ec481b39ad

## Subsequent updates - validate with previous entity statement

    python update-entity-statement.py -u https://tunnistus-te.telia.fi/.well-known/openid-federation --previous openid-federation.jwt

# Launch server

    python client.py

