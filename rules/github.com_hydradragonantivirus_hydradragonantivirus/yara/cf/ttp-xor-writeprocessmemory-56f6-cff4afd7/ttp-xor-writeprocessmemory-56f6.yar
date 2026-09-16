rule TTP_XOR_WriteProcessMemory_56f6 {
  strings:
    $key_56f6 = { 01 84 [2] 33 a6 [2] 35 93 [2] 1b 93 [2] 24 8f }

  condition:
    any of them
}