rule TTP_XOR_WriteProcessMemory_ea8b {
  strings:
    $key_ea8b = { bd f9 [2] 8f db [2] 89 ee [2] a7 ee [2] 98 f2 }

  condition:
    any of them
}