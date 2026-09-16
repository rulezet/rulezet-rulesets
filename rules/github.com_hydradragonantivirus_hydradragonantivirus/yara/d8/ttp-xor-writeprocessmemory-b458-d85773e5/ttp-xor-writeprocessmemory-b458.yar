rule TTP_XOR_WriteProcessMemory_b458 {
  strings:
    $key_b458 = { e3 2a [2] d1 08 [2] d7 3d [2] f9 3d [2] c6 21 }

  condition:
    any of them
}