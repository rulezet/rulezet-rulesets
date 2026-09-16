rule TTP_XOR_WriteProcessMemory_b3f1 {
  strings:
    $key_b3f1 = { e4 83 [2] d6 a1 [2] d0 94 [2] fe 94 [2] c1 88 }

  condition:
    any of them
}