rule TTP_XOR_WriteProcessMemory_02c5 {
  strings:
    $key_02c5 = { 55 b7 [2] 67 95 [2] 61 a0 [2] 4f a0 [2] 70 bc }

  condition:
    any of them
}