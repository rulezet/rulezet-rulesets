rule TTP_XOR_WriteProcessMemory_7260 {
  strings:
    $key_7260 = { 25 12 [2] 17 30 [2] 11 05 [2] 3f 05 [2] 00 19 }

  condition:
    any of them
}