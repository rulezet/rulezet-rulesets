rule TTP_XOR_WriteProcessMemory_08d5 {
  strings:
    $key_08d5 = { 5f a7 [2] 6d 85 [2] 6b b0 [2] 45 b0 [2] 7a ac }

  condition:
    any of them
}