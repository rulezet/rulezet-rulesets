rule TTP_XOR_WriteProcessMemory_0f9c {
  strings:
    $key_0f9c = { 58 ee [2] 6a cc [2] 6c f9 [2] 42 f9 [2] 7d e5 }

  condition:
    any of them
}