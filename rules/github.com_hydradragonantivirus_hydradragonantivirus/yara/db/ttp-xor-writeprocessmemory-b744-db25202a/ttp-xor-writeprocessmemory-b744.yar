rule TTP_XOR_WriteProcessMemory_b744 {
  strings:
    $key_b744 = { e0 36 [2] d2 14 [2] d4 21 [2] fa 21 [2] c5 3d }

  condition:
    any of them
}