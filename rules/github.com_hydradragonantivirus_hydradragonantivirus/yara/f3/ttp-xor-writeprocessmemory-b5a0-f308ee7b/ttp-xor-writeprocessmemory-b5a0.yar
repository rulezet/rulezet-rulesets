rule TTP_XOR_WriteProcessMemory_b5a0 {
  strings:
    $key_b5a0 = { e2 d2 [2] d0 f0 [2] d6 c5 [2] f8 c5 [2] c7 d9 }

  condition:
    any of them
}