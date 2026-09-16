rule TTP_XOR_WriteProcessMemory_5f9c {
  strings:
    $key_5f9c = { 08 ee [2] 3a cc [2] 3c f9 [2] 12 f9 [2] 2d e5 }

  condition:
    any of them
}