rule TTP_XOR_WriteProcessMemory_4645 {
  strings:
    $key_4645 = { 11 37 [2] 23 15 [2] 25 20 [2] 0b 20 [2] 34 3c }

  condition:
    any of them
}