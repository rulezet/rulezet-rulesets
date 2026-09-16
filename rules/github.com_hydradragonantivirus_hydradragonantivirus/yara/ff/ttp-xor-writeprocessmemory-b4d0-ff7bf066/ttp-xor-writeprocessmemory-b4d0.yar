rule TTP_XOR_WriteProcessMemory_b4d0 {
  strings:
    $key_b4d0 = { e3 a2 [2] d1 80 [2] d7 b5 [2] f9 b5 [2] c6 a9 }

  condition:
    any of them
}