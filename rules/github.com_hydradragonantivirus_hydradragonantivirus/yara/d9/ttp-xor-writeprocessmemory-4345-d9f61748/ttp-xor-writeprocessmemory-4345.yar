rule TTP_XOR_WriteProcessMemory_4345 {
  strings:
    $key_4345 = { 14 37 [2] 26 15 [2] 20 20 [2] 0e 20 [2] 31 3c }

  condition:
    any of them
}