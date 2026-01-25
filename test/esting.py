import os

# -------------------------------------------------------------------------
# EXPANDED TEST FILE: NEW SERVICES & GENERIC PATTERNS
# These mimic real patterns (Prefixes, Lengths, Charsets) but are fake.
# -------------------------------------------------------------------------

def test_new_services():
    """
    Tests specific prefixes for popular services you might add later.
    """
    
    # 1. Twilio Account SID (Always starts with AC and is 34 chars)
    # Regex look-alike: ^AC[a-z0-9]{32}$
    twilio_sid = "AC" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    
    # 2. Twilio API Key (Starts with SK)
    twilio_key = "SK1234567890abcdef1234567890abcdef"

    # 3. SendGrid API Key (Starts with SG.)
    # Structure: SG. [22 chars] . [43 chars]
    sendgrid_token = "SG.RxAbCdEfGhIjKlMnOpQrSt." + "UvWxYz1234567890abcdefghijklmnopqrstuvwxyz1"

    # 4. Heroku API Key (UUID Format: 8-4-4-4-12 hex)
    # Your scanner might catch this via "variable name" detection
    heroku_api_key = "05330368-d069-42b3-961d-1234567890ab"

    # 5. Mailgun API Key (Starts with key-)
    mailgun_key = "key-" + "3ax6xnJP29jd8Fh7n1"

    # 6. Square Access Token (Starts with sq0atp-)
    square_token = "sq0atp-AbCdEfGhIjKlMnOpQrStUv"

def test_social_media_tokens():
    """
    Tests keys for social platforms.
    """

    # 1. Facebook Access Token (Pipe separated ID|Secret)
    # Often looks like: 1234567890|AbCdEfGhIjKlMnOpQrStUvWxYz
    facebook_token = "123456789012345|" + "AbCdEfGhIjKlMnOpQrStUvWxYz"

    # 2. Twitter/X Bearer Token (Starts with AAAAAAAAAAAAAAAAAAAA)
    twitter_bearer = "AAAAAAAAAAAAAAAAAAAA" + "AP%2ABCDE1234567890abcdefghijklmnopqrstuvwxyz"

    # 3. LinkedIn Client Secret (16 characters, alphanumeric)
    linkedin_secret = "A1b2C3d4E5f6G7h8"

def test_generic_patterns():
    """
    Tests if your scanner catches "Generic" secrets based on 
    Variable Names or Keywords (like 'password', 'secret', 'token').
    """

    # 1. Generic API Key (High Entropy Hex)
    # This relies on your scanner flagging the variable name "api_key"
    my_app_api_key = "3f8a9c2d1e5b7f6a4c2d1e5b7f6a4c2d"

    # 2. Generic Bearer Token (Base64 URL Safe)
    # Obfuscated split
    auth_header = "eyJhbGciOiJIUzI1NiIsInR5cCD6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"

    # 3. Database Connection String (Password in URL)
    # Scanner should catch "postgres://" pattern
    db_url = "postgres://user:" + "Sup3rS3cr3tP4ssw0rd!" + "@localhost:5432/mydb"

    # 4. RSA Private Key Header (PEM Format)
    # If checking for "-----BEGIN RSA PRIVATE KEY-----"
    rsa_private_key = "-----BEGIN RSA PRIVATE KEY-----\n" \
                      "MIIEowIBAAKCAQEA..."

    # 5. Hardcoded Password Variable
    # Simple keyword match test
    admin_password = "CorrectHorseBatteryStaple123!" 

def test_tricky_obfuscation():
    """
    Tricky ways developers hide secrets that aren't just 'split strings'.
    """

    # 1. Comment Insertion (Hard for regex to skip)
    # python allows this: "part1" "part2"
    stripe_comment_split = "sk_live_" "12345" # Hidden split

    # 2. Multiple Splits
    # "A" + "B" + "C" + "D"
    long_split_key = "AIza" + "SyD-" + "Fke9" + "_3kL"