rule TTP_XOR_WriteProcessMemory_b5d1 {
  strings:
    $key_b5d1 = { e2 a3 [2] d0 81 [2] d6 b4 [2] f8 b4 [2] c7 a8 }

  condition:
    any of them
}