rule TTP_XOR_WriteProcessMemory_b4a0 {
  strings:
    $key_b4a0 = { e3 d2 [2] d1 f0 [2] d7 c5 [2] f9 c5 [2] c6 d9 }

  condition:
    any of them
}