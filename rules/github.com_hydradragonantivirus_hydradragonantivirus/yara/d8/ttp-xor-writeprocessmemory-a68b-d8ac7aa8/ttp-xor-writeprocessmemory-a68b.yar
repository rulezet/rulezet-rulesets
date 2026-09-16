rule TTP_XOR_WriteProcessMemory_a68b {
  strings:
    $key_a68b = { f1 f9 [2] c3 db [2] c5 ee [2] eb ee [2] d4 f2 }

  condition:
    any of them
}