rule TTP_XOR_WriteProcessMemory_a468 {
  strings:
    $key_a468 = { f3 1a [2] c1 38 [2] c7 0d [2] e9 0d [2] d6 11 }

  condition:
    any of them
}