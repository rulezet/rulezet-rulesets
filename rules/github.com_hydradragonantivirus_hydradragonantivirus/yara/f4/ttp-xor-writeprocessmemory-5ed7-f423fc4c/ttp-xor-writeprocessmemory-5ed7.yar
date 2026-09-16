rule TTP_XOR_WriteProcessMemory_5ed7 {
  strings:
    $key_5ed7 = { 09 a5 [2] 3b 87 [2] 3d b2 [2] 13 b2 [2] 2c ae }

  condition:
    any of them
}