rule SUSP_Obfuscated_Powershell_decimal_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_xor"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_decimal_xor = "112 111 119 101 114 115 104 101 108 108" xor(0x01-0xff) ascii wide
    $PowerShell_decimal_xor = "80 111 119 101 114 83 104 101 108 108" xor(0x01-0xff) ascii wide
    $Powershell_decimal_xor = "80 111 119 101 114 115 104 101 108 108" xor(0x01-0xff) ascii wide

  condition:
    any of them
}