rule TTP_XOR_WriteProcessMemory_b5d6 {
  strings:
    $key_b5d6 = { e2 a4 [2] d0 86 [2] d6 b3 [2] f8 b3 [2] c7 af }

  condition:
    any of them
}