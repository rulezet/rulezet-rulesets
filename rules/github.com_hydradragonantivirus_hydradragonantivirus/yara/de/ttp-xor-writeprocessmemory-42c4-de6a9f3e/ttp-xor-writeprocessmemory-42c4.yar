rule TTP_XOR_WriteProcessMemory_42c4 {
  strings:
    $key_42c4 = { 15 b6 [2] 27 94 [2] 21 a1 [2] 0f a1 [2] 30 bd }

  condition:
    any of them
}