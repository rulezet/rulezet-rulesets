rule TTP_XOR_WriteProcessMemory_b568 {
  strings:
    $key_b568 = { e2 1a [2] d0 38 [2] d6 0d [2] f8 0d [2] c7 11 }

  condition:
    any of them
}