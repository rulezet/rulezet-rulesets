rule SUSP_Obfuscated_Mozilla_hex_enc_str_spaces {
  meta:
    author      = "Greg Lesnewich"
    description = "track obfuscated Mozilla strings"
    date        = "2024-02-13"
    version     = "1.0"
    DaysOfYara  = "44/100"

  strings:
    $Mozilla_hex_enc_str_spaces = "4d 6f 7a 69 6c 6c 61" nocase ascii wide

  condition:
    all of them
}