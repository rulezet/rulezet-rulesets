rule TTP_XOR_WriteProcessMemory_b3d4 {
  strings:
    $key_b3d4 = { e4 a6 [2] d6 84 [2] d0 b1 [2] fe b1 [2] c1 ad }

  condition:
    any of them
}