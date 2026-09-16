rule TTP_XOR_WriteProcessMemory_0f66 {
  strings:
    $key_0f66 = { 58 14 [2] 6a 36 [2] 6c 03 [2] 42 03 [2] 7d 1f }

  condition:
    any of them
}