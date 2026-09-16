rule TTP_XOR_WriteProcessMemory_b551 {
  strings:
    $key_b551 = { e2 23 [2] d0 01 [2] d6 34 [2] f8 34 [2] c7 28 }

  condition:
    any of them
}