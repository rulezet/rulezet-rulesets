rule TTP_XOR_WriteProcessMemory_0f8b {
  strings:
    $key_0f8b = { 58 f9 [2] 6a db [2] 6c ee [2] 42 ee [2] 7d f2 }

  condition:
    any of them
}