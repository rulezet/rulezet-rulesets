rule SUSP_Obfuscated_Powershell_reverse_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via reverse_xor"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "32/100"

  strings:
    $powershell_reverse_xor = "llehsrewop" xor(0x01-0xff) ascii wide
    $PowerShell_reverse_xor = "llehSrewoP" xor(0x01-0xff) ascii wide
    $Powershell_reverse_xor = "llehsrewoP" xor(0x01-0xff) ascii wide

  condition:
    any of them
}