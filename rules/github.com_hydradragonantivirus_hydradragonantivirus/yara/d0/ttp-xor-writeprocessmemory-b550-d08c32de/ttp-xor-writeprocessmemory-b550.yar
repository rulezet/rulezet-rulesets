rule TTP_XOR_WriteProcessMemory_b550 {
  strings:
    $key_b550 = { e2 22 [2] d0 00 [2] d6 35 [2] f8 35 [2] c7 29 }

  condition:
    any of them
}