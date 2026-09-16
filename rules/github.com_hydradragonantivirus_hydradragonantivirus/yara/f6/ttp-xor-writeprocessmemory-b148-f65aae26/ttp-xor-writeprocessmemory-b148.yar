rule TTP_XOR_WriteProcessMemory_b148 {
  strings:
    $key_b148 = { e6 3a [2] d4 18 [2] d2 2d [2] fc 2d [2] c3 31 }

  condition:
    any of them
}