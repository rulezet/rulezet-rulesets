rule TTP_XOR_WriteProcessMemory_8645 {
  strings:
    $key_8645 = { d1 37 [2] e3 15 [2] e5 20 [2] cb 20 [2] f4 3c }

  condition:
    any of them
}