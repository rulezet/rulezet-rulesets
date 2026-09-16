rule TTP_XOR_WriteProcessMemory_3ed7 {
  strings:
    $key_3ed7 = { 69 a5 [2] 5b 87 [2] 5d b2 [2] 73 b2 [2] 4c ae }

  condition:
    any of them
}