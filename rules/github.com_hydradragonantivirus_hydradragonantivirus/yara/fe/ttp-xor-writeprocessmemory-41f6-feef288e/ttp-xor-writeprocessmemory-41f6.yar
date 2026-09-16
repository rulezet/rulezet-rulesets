rule TTP_XOR_WriteProcessMemory_41f6 {
  strings:
    $key_41f6 = { 16 84 [2] 24 a6 [2] 22 93 [2] 0c 93 [2] 33 8f }

  condition:
    any of them
}