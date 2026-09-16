rule TTP_XOR_WriteProcessMemory_b344 {
  strings:
    $key_b344 = { e4 36 [2] d6 14 [2] d0 21 [2] fe 21 [2] c1 3d }

  condition:
    any of them
}