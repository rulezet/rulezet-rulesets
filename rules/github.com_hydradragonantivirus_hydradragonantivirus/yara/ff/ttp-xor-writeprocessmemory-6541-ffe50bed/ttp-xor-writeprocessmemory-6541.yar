rule TTP_XOR_WriteProcessMemory_6541 {
  strings:
    $key_6541 = { 32 33 [2] 00 11 [2] 06 24 [2] 28 24 [2] 17 38 }

  condition:
    any of them
}