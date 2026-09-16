rule TTP_XOR_WriteProcessMemory_b364 {
  strings:
    $key_b364 = { e4 16 [2] d6 34 [2] d0 01 [2] fe 01 [2] c1 1d }

  condition:
    any of them
}