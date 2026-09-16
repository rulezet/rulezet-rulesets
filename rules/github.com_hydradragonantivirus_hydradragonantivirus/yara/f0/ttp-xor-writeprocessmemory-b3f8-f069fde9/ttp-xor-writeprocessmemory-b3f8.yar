rule TTP_XOR_WriteProcessMemory_b3f8 {
  strings:
    $key_b3f8 = { e4 8a [2] d6 a8 [2] d0 9d [2] fe 9d [2] c1 81 }

  condition:
    any of them
}