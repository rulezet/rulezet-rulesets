rule TTP_XOR_WriteProcessMemory_0f56 {
  strings:
    $key_0f56 = { 58 24 [2] 6a 06 [2] 6c 33 [2] 42 33 [2] 7d 2f }

  condition:
    any of them
}