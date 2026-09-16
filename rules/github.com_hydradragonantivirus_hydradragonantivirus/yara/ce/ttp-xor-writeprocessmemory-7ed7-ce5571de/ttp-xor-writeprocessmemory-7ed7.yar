rule TTP_XOR_WriteProcessMemory_7ed7 {
  strings:
    $key_7ed7 = { 29 a5 [2] 1b 87 [2] 1d b2 [2] 33 b2 [2] 0c ae }

  condition:
    any of them
}