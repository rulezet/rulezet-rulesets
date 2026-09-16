rule TTP_XOR_WriteProcessMemory_4351 {
  strings:
    $key_4351 = { 14 23 [2] 26 01 [2] 20 34 [2] 0e 34 [2] 31 28 }

  condition:
    any of them
}