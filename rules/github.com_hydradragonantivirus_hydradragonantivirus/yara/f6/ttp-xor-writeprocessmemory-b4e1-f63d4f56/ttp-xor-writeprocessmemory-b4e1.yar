rule TTP_XOR_WriteProcessMemory_b4e1 {
  strings:
    $key_b4e1 = { e3 93 [2] d1 b1 [2] d7 84 [2] f9 84 [2] c6 98 }

  condition:
    any of them
}