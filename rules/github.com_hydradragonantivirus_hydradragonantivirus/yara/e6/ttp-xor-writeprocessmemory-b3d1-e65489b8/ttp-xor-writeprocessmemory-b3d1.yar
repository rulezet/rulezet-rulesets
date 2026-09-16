rule TTP_XOR_WriteProcessMemory_b3d1 {
  strings:
    $key_b3d1 = { e4 a3 [2] d6 81 [2] d0 b4 [2] fe b4 [2] c1 a8 }

  condition:
    any of them
}