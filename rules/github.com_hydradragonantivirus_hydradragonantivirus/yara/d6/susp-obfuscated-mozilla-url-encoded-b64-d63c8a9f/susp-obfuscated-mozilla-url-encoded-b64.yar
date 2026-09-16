rule SUSP_Obfuscated_Mozilla_url_encoded_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "track obfuscated Mozilla strings"
    date        = "2024-02-13"
    version     = "1.0"
    DaysOfYara  = "44/100"

  strings:
    $Mozilla_url_encoded_b64 = "4d%6f%7a%69%6c%6c%61" base64 base64wide

  condition:
    all of them
}