rule TTP_XOR_WriteProcessMemory_a3d0 {
  strings:
    $key_a3d0 = { f4 a2 [2] c6 80 [2] c0 b5 [2] ee b5 [2] d1 a9 }

  condition:
    any of them
}