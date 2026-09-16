rule TTP_XOR_WriteProcessMemory_8e81 {
  strings:
    $key_8e81 = { d9 f3 [2] eb d1 [2] ed e4 [2] c3 e4 [2] fc f8 }

  condition:
    any of them
}