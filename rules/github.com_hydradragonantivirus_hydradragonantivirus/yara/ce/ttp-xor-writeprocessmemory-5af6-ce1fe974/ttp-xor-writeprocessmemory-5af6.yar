rule TTP_XOR_WriteProcessMemory_5af6 {
  strings:
    $key_5af6 = { 0d 84 [2] 3f a6 [2] 39 93 [2] 17 93 [2] 28 8f }

  condition:
    any of them
}