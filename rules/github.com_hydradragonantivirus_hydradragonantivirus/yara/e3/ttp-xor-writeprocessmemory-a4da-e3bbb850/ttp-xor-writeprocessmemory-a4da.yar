rule TTP_XOR_WriteProcessMemory_a4da {
  strings:
    $key_a4da = { f3 a8 [2] c1 8a [2] c7 bf [2] e9 bf [2] d6 a3 }

  condition:
    any of them
}