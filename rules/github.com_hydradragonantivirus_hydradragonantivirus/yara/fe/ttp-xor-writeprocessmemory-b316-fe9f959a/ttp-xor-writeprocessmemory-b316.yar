rule TTP_XOR_WriteProcessMemory_b316 {
  strings:
    $key_b316 = { e4 64 [2] d6 46 [2] d0 73 [2] fe 73 [2] c1 6f }

  condition:
    any of them
}