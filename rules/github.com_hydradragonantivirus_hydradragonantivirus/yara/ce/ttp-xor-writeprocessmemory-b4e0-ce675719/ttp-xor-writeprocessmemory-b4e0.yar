rule TTP_XOR_WriteProcessMemory_b4e0 {
  strings:
    $key_b4e0 = { e3 92 [2] d1 b0 [2] d7 85 [2] f9 85 [2] c6 99 }

  condition:
    any of them
}