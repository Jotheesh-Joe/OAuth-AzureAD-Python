import jwt
from jwksutils import rsa_pem_from_jwk

jwks = {
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "-KI3Q9nNR7bRofxmeZoXqbHZGew",
      "x5t": "-KI3Q9nNR7bRofxmeZoXqbHZGew",
      "n": "tJL6Wr2JUsxLyNezPQh1J6zn6wSoDAhgRYSDkaMuEHy75VikiB8wg25WuR96gdMpookdlRvh7SnRvtjQN9b5m4zJCMpSRcJ5DuXl4mcd7Cg3Zp1C5-JmMq8J7m7OS9HpUQbA1yhtCHqP7XA4UnQI28J-TnGiAa3viPLlq0663Cq6hQw7jYo5yNjdJcV5-FS-xNV7UHR4zAMRruMUHxte1IZJzbJmxjKoEjJwDTtcd6DkI3yrkmYt8GdQmu0YBHTJSZiz-M10CY3LbvLzf-tbBNKQ_gfnGGKF7MvRCmPA_YF_APynrIG7p4vPDRXhpG3_CIt317NyvGoIwiv0At83kQ",
      "e": "AQAB",
      "x5c": [
        "MIIDBTCCAe2gAwIBAgIQGQ6YG6NleJxJGDRAwAd/ZTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIyMTAwMjE4MDY0OVoXDTI3MTAwMjE4MDY0OVowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALSS+lq9iVLMS8jXsz0IdSes5+sEqAwIYEWEg5GjLhB8u+VYpIgfMINuVrkfeoHTKaKJHZUb4e0p0b7Y0DfW+ZuMyQjKUkXCeQ7l5eJnHewoN2adQufiZjKvCe5uzkvR6VEGwNcobQh6j+1wOFJ0CNvCfk5xogGt74jy5atOutwquoUMO42KOcjY3SXFefhUvsTVe1B0eMwDEa7jFB8bXtSGSc2yZsYyqBIycA07XHeg5CN8q5JmLfBnUJrtGAR0yUmYs/jNdAmNy27y83/rWwTSkP4H5xhihezL0QpjwP2BfwD8p6yBu6eLzw0V4aRt/wiLd9ezcrxqCMIr9ALfN5ECAwEAAaMhMB8wHQYDVR0OBBYEFJcSH+6Eaqucndn9DDu7Pym7OA8rMA0GCSqGSIb3DQEBCwUAA4IBAQADKkY0PIyslgWGmRDKpp/5PqzzM9+TNDhXzk6pw8aESWoLPJo90RgTJVf8uIj3YSic89m4ftZdmGFXwHcFC91aFe3PiDgCiteDkeH8KrrpZSve1pcM4SNjxwwmIKlJdrbcaJfWRsSoGFjzbFgOecISiVaJ9ZWpb89/+BeAz1Zpmu8DSyY22dG/K6ZDx5qNFg8pehdOUYY24oMamd4J2u2lUgkCKGBZMQgBZFwk+q7H86B/byGuTDEizLjGPTY/sMms1FAX55xBydxrADAer/pKrOF1v7Dq9C1Z9QVcm5D9G4DcenyWUdMyK43NXbVQLPxLOng51KO9icp2j4U7pwHP"
      ]
    },
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "9GmnyFPkhc3hOuR22mvSvgnLo7Y",
      "x5t": "9GmnyFPkhc3hOuR22mvSvgnLo7Y",
      "n": "z_w-5U4eZwenXYnEgt2rCN-753YQ7RN8ykiNprNiLl4ilpwAGLWF1cssoRflsSiBVZcCSwUzUwsifG7sbRq9Vc8RFs72Gg0AUwPsJFUqNttMg3Ot-wTqsZtE5GNSBUSqnI-iWoZfjw-uLsS0u4MfzP8Fpkd-rzRlifuIAYK8Ffi1bldkszeBzQbBZbXFwiw5uTf8vEAkH_IAdB732tQAsNXpWWYDV74nKAiwLlDS5FWVs2S2T-MPNAg28MLxYfRhW2bUpd693inxI8WTSLRncouzMImJF4XeMG2ZRZ0z_KJra_uzzMCLbILtpnLA95ysxWw-4ygm3MxN2iBM2IaJeQ",
      "e": "AQAB",
      "x5c": [
        "MIIC/jCCAeagAwIBAgIJAOCJOVRxNKcNMA0GCSqGSIb3DQEBCwUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMjMwODI4MjAwMjQwWhcNMjgwODI4MjAwMjQwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz/w+5U4eZwenXYnEgt2rCN+753YQ7RN8ykiNprNiLl4ilpwAGLWF1cssoRflsSiBVZcCSwUzUwsifG7sbRq9Vc8RFs72Gg0AUwPsJFUqNttMg3Ot+wTqsZtE5GNSBUSqnI+iWoZfjw+uLsS0u4MfzP8Fpkd+rzRlifuIAYK8Ffi1bldkszeBzQbBZbXFwiw5uTf8vEAkH/IAdB732tQAsNXpWWYDV74nKAiwLlDS5FWVs2S2T+MPNAg28MLxYfRhW2bUpd693inxI8WTSLRncouzMImJF4XeMG2ZRZ0z/KJra/uzzMCLbILtpnLA95ysxWw+4ygm3MxN2iBM2IaJeQIDAQABoyEwHzAdBgNVHQ4EFgQU/wzRzxsifMCz54SZ3HuF4P4jtzowDQYJKoZIhvcNAQELBQADggEBACaWlbJTObDai8+wmskHedKYb3FCfTwvH/sCRsygHIeDIi23CpoWeKt5FwXsSeqDMd0Hb6IMtYDG5rfGvhkNfunt3sutK0VpZZMNdSBmIXaUx4mBRRUsG4hpeWRrHRgTnxweDDVw4Mv+oYCmpY7eZ4SenISkSd/4qrXzFaI9NeZCY7Jg9vg1bev+NaUtD3C4As6GQ+mN8Rm2NG9vzgTDlKf4Wb5Exy7u9dMW1TChiy28ieVkETKdqwXcbhqM8GOLBUFicdmgP2y9aDGjb89BuaeoHJCGpWWCi3UZth14clVzC6p7ZD6fFx5tKMOL/hQvs3ugGtvFDWCsvcT8bB84RO8="
      ]
    },
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "lHLIu4moKqzPcokwlfCRPHyjl5g",
      "x5t": "lHLIu4moKqzPcokwlfCRPHyjl5g",
      "n": "xlc-u9LJvOdbwAsgsYZpaJrgmrGHaEkoa_3_7Jvu4-Hb8LNtszrQy5Ik4CXgQ_uiLPt4-ePprX3klFAx91ahfd5LwX6mEQPT8WuHMDunx8MaNQrYNVvnOI1L5NxFBFV_6ghi_0d-cOslErcTMML2lbMCSjQ8jwltxz1Oy-Hd9wdY2pz2YC3WR4tHzAGreWGeOB2Vs2NLGv0U3CGSCMqpM9vxbWLZQPuCNpKF93RkxHj5bLng9U_rM6YScacEnTFlKIOOrk4pcVVdoSNNIK2uNUs1hHS1mBXuQjfceghzj3QQYHfp1Z5qWXPRIw3PDyn_1Sowe5UljLurkpj_8m3KnQ",
      "e": "AQAB",
      "x5c": [
        "MIIC6TCCAdGgAwIBAgIIT3fcexMa3ggwDQYJKoZIhvcNAQELBQAwIzEhMB8GA1UEAxMYbG9naW4ubWljcm9zb2Z0b25saW5lLnVzMB4XDTIzMDcxNDAwNDU0NFoXDTI4MDcxNDAwNDU0NFowIzEhMB8GA1UEAxMYbG9naW4ubWljcm9zb2Z0b25saW5lLnVzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxlc+u9LJvOdbwAsgsYZpaJrgmrGHaEkoa/3/7Jvu4+Hb8LNtszrQy5Ik4CXgQ/uiLPt4+ePprX3klFAx91ahfd5LwX6mEQPT8WuHMDunx8MaNQrYNVvnOI1L5NxFBFV/6ghi/0d+cOslErcTMML2lbMCSjQ8jwltxz1Oy+Hd9wdY2pz2YC3WR4tHzAGreWGeOB2Vs2NLGv0U3CGSCMqpM9vxbWLZQPuCNpKF93RkxHj5bLng9U/rM6YScacEnTFlKIOOrk4pcVVdoSNNIK2uNUs1hHS1mBXuQjfceghzj3QQYHfp1Z5qWXPRIw3PDyn/1Sowe5UljLurkpj/8m3KnQIDAQABoyEwHzAdBgNVHQ4EFgQUCSJrrznFYz1BLqd17S8HFjGrAOAwDQYJKoZIhvcNAQELBQADggEBAAQHNudtmYpeh9x5+rGDVy6OYpTnQ2D5+rmgOHM5yRvgEnFBNuZ6bnr3Ap9nb6EM08juYKPaVyhkV+5axMl+dT8KOuCgrfcKvXqzdQ3BgVFkyU9XfajHzq3JALYpNkixCs/BvqRhXx2ecYxFHB2D671cOwhYIaMZdGtbmOOk8puYSgJ9DBqqn3pLksHmxLP656l/U3hPATTCdfDaNcTagIPx+Q2d9RBn8zOIa/p4CLsu3E0aJfDw3ljPD8inLJ2mpKq06TBfd5Rr/auwipb4J8Y/PHhef8b2kOf42fikIKAP538k9lLsXSowyPWn7KZDTEsku7xpyqvKvEiFkmaV+RY="
      ]
    }
  ]
}




class InvalidAuthorizationToken(Exception):
    def __init__(self, details):
        super().__init__('Invalid authorization token: ' + details)


def get_kid(token):
    headers = jwt.get_unverified_header(token)
    if not headers:
        raise InvalidAuthorizationToken('missing headers')
    try:
        return headers['kid']
    except KeyError:
        raise InvalidAuthorizationToken('missing kid')


def get_jwk(kid):
    for jwk in jwks.get('keys'):
        if jwk.get('kid') == kid:
            return jwk
    raise InvalidAuthorizationToken('kid not recognized')


def get_public_key(token):
    return rsa_pem_from_jwk(get_jwk(get_kid(token)))


def validate_jwt(jwt_to_validate, valid_audiences, issuer):
    public_key = get_public_key(jwt_to_validate)

    decoded = jwt.decode(jwt_to_validate,
                         public_key,
                         verify=True,
                         algorithms=['RS256'],
                         audience=valid_audiences,
                         issuer=issuer)
    return decoded


def validate_jwt_auth(jwt_to_validate, valid_audiences, issuer):
    try:
        public_key = get_public_key(jwt_to_validate)

        decoded = jwt.decode(jwt_to_validate,
                            public_key,
                            verify=True,
                            algorithms=['RS256'],
                            audience=valid_audiences,
                            issuer=issuer)
        return True
    except Exception as ex:
        print('The JWT is not valid!')
        return False
