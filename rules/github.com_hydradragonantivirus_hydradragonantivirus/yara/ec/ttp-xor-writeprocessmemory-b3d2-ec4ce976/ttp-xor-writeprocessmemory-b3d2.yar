rule TTP_XOR_WriteProcessMemory_b3d2 {
  strings:
    $key_b3d2 = { e4 a0 [2] d6 82 [2] d0 b7 [2] fe b7 [2] c1 ab }

  condition:
    any of them
}