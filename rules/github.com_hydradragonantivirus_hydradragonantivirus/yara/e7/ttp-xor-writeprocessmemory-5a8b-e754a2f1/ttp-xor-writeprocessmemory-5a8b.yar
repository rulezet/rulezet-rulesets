rule TTP_XOR_WriteProcessMemory_5a8b {
  strings:
    $key_5a8b = { 0d f9 [2] 3f db [2] 39 ee [2] 17 ee [2] 28 f2 }

  condition:
    any of them
}