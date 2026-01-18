def deobfuscate_line(line):
    clean = line
    clean = clean.replace('"+"', '')
    clean = clean.replace("'+'", "")
    clean = clean.replace('" + "', '')
    clean = clean.replace("' + '", "")
    return clean

# Your example
bad_line = 'Google_API = "AIzaSyD-Fke9_3kL1"+"mNopQrStUvWxYz12345678"'

print(f"Original: {bad_line}")
print(f"Cleaned:  {deobfuscate_line(bad_line)}")

# Expected Output:
# Original: google_api = "Asdasasadsadf21212!@"+"21dasa21#@!#14"
# Cleaned:  google_api = "Asdasasadsadf21212!@21dasa21#@!#14"