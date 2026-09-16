rule TTP_XOR_WriteProcessMemory_63ad {
  strings:
    $key_63ad = { 34 df [2] 06 fd [2] 00 c8 [2] 2e c8 [2] 11 d4 }

  condition:
    any of them
}