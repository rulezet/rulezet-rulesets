rule TTP_XOR_WriteProcessMemory_b5c1 {
  strings:
    $key_b5c1 = { e2 b3 [2] d0 91 [2] d6 a4 [2] f8 a4 [2] c7 b8 }

  condition:
    any of them
}