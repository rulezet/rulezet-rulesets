rule TTP_XOR_WriteProcessMemory_4677 {
  strings:
    $key_4677 = { 11 05 [2] 23 27 [2] 25 12 [2] 0b 12 [2] 34 0e }

  condition:
    any of them
}