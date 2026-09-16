rule TTP_XOR_WriteProcessMemory_b351 {
  strings:
    $key_b351 = { e4 23 [2] d6 01 [2] d0 34 [2] fe 34 [2] c1 28 }

  condition:
    any of them
}