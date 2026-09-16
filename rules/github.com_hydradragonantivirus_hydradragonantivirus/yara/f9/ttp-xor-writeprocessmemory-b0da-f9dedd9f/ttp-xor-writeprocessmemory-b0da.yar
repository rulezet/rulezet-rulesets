rule TTP_XOR_WriteProcessMemory_b0da {
  strings:
    $key_b0da = { e7 a8 [2] d5 8a [2] d3 bf [2] fd bf [2] c2 a3 }

  condition:
    any of them
}