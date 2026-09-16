rule TTP_XOR_WriteProcessMemory_1e9c {
  strings:
    $key_1e9c = { 49 ee [2] 7b cc [2] 7d f9 [2] 53 f9 [2] 6c e5 }

  condition:
    any of them
}