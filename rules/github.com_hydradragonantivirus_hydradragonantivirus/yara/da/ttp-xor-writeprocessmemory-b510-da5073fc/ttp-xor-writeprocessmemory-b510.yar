rule TTP_XOR_WriteProcessMemory_b510 {
  strings:
    $key_b510 = { e2 62 [2] d0 40 [2] d6 75 [2] f8 75 [2] c7 69 }

  condition:
    any of them
}