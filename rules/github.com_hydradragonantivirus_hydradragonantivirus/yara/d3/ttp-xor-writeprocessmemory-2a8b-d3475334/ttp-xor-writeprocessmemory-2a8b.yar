rule TTP_XOR_WriteProcessMemory_2a8b {
  strings:
    $key_2a8b = { 7d f9 [2] 4f db [2] 49 ee [2] 67 ee [2] 58 f2 }

  condition:
    any of them
}