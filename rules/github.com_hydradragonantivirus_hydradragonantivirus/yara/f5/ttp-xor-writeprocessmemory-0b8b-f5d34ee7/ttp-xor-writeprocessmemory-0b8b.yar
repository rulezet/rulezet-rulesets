rule TTP_XOR_WriteProcessMemory_0b8b {
  strings:
    $key_0b8b = { 5c f9 [2] 6e db [2] 68 ee [2] 46 ee [2] 79 f2 }

  condition:
    any of them
}