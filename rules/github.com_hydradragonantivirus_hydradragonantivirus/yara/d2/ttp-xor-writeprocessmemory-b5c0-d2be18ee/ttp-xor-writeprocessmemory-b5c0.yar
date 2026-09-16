rule TTP_XOR_WriteProcessMemory_b5c0 {
  strings:
    $key_b5c0 = { e2 b2 [2] d0 90 [2] d6 a5 [2] f8 a5 [2] c7 b9 }

  condition:
    any of them
}