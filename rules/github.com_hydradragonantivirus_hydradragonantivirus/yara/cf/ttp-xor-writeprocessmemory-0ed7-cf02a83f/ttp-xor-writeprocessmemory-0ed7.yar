rule TTP_XOR_WriteProcessMemory_0ed7 {
  strings:
    $key_0ed7 = { 59 a5 [2] 6b 87 [2] 6d b2 [2] 43 b2 [2] 7c ae }

  condition:
    any of them
}