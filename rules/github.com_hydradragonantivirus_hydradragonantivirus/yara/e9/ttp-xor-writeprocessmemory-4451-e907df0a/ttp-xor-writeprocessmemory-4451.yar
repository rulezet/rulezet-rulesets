rule TTP_XOR_WriteProcessMemory_4451 {
  strings:
    $key_4451 = { 13 23 [2] 21 01 [2] 27 34 [2] 09 34 [2] 36 28 }

  condition:
    any of them
}