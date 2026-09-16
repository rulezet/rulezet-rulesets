rule TTP_XOR_WriteProcessMemory_0f26 {
  strings:
    $key_0f26 = { 58 54 [2] 6a 76 [2] 6c 43 [2] 42 43 [2] 7d 5f }

  condition:
    any of them
}