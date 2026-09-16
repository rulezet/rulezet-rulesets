rule TTP_XOR_WriteProcessMemory_5f85 {
  strings:
    $key_5f85 = { 08 f7 [2] 3a d5 [2] 3c e0 [2] 12 e0 [2] 2d fc }

  condition:
    any of them
}