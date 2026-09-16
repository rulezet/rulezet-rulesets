rule TTP_XOR_WriteProcessMemory_b354 {
  strings:
    $key_b354 = { e4 26 [2] d6 04 [2] d0 31 [2] fe 31 [2] c1 2d }

  condition:
    any of them
}