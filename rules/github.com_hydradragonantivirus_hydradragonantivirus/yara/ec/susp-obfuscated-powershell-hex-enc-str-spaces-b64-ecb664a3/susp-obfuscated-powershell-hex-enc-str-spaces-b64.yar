rule SUSP_Obfuscated_Powershell_hex_enc_str_spaces_b64 {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_spaces_b64"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_hex_enc_str_spaces_b64 = "70 6f 77 65 72 73 68 65 6c 6c" base64 base64wide
    $PowerShell_hex_enc_str_spaces_b64 = "50 6f 77 65 72 53 68 65 6c 6c" base64 base64wide
    $Powershell_hex_enc_str_spaces_b64 = "50 6f 77 65 72 73 68 65 6c 6c" base64 base64wide

  condition:
    any of them
}