rule TTP_XOR_WriteProcessMemory_a6da {
  strings:
    $key_a6da = { f1 a8 [2] c3 8a [2] c5 bf [2] eb bf [2] d4 a3 }

  condition:
    any of them
}