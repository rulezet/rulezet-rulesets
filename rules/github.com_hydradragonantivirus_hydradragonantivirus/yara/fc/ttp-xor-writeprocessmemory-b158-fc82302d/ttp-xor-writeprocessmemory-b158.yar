rule TTP_XOR_WriteProcessMemory_b158 {
  strings:
    $key_b158 = { e6 2a [2] d4 08 [2] d2 3d [2] fc 3d [2] c3 21 }

  condition:
    any of them
}