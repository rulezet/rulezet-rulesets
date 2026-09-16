rule SUSP_Obfuscated_Mozilla_hex_enc_str_reversed_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "track obfuscated Mozilla strings"
    date        = "2024-02-13"
    version     = "1.0"
    DaysOfYara  = "44/100"

  strings:
    $Mozilla_hex_enc_str_reversed_xor = "16c6c696a7f6d4" xor(0x01-0xff) ascii wide

  condition:
    all of them
}