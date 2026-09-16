rule TTP_XOR_WriteProcessMemory_5967 {
  strings:
    $key_5967 = { 0e 15 [2] 3c 37 [2] 3a 02 [2] 14 02 [2] 2b 1e }

  condition:
    any of them
}