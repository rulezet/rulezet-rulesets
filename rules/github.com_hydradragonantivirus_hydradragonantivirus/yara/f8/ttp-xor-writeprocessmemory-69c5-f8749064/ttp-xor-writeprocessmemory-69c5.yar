rule TTP_XOR_WriteProcessMemory_69c5 {
  strings:
    $key_69c5 = { 3e b7 [2] 0c 95 [2] 0a a0 [2] 24 a0 [2] 1b bc }

  condition:
    any of them
}