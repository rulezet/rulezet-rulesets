rule TTP_XOR_WriteProcessMemory_4329 {
  strings:
    $key_4329 = { 14 5b [2] 26 79 [2] 20 4c [2] 0e 4c [2] 31 50 }

  condition:
    any of them
}