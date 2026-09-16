rule TTP_XOR_WriteProcessMemory_b3f6 {
  strings:
    $key_b3f6 = { e4 84 [2] d6 a6 [2] d0 93 [2] fe 93 [2] c1 8f }

  condition:
    any of them
}