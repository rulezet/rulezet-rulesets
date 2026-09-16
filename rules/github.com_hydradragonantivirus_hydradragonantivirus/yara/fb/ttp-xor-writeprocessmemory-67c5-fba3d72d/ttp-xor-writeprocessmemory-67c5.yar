rule TTP_XOR_WriteProcessMemory_67c5 {
  strings:
    $key_67c5 = { 30 b7 [2] 02 95 [2] 04 a0 [2] 2a a0 [2] 15 bc }

  condition:
    any of them
}