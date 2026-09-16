rule TTP_XOR_WriteProcessMemory_17c5 {
  strings:
    $key_17c5 = { 40 b7 [2] 72 95 [2] 74 a0 [2] 5a a0 [2] 65 bc }

  condition:
    any of them
}