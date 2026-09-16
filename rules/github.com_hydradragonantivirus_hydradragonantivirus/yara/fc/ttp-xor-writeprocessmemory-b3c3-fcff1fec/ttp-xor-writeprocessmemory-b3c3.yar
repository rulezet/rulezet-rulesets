rule TTP_XOR_WriteProcessMemory_b3c3 {
  strings:
    $key_b3c3 = { e4 b1 [2] d6 93 [2] d0 a6 [2] fe a6 [2] c1 ba }

  condition:
    any of them
}