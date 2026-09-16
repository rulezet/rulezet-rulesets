rule TTP_XOR_WriteProcessMemory_73ad {
  strings:
    $key_73ad = { 24 df [2] 16 fd [2] 10 c8 [2] 3e c8 [2] 01 d4 }

  condition:
    any of them
}