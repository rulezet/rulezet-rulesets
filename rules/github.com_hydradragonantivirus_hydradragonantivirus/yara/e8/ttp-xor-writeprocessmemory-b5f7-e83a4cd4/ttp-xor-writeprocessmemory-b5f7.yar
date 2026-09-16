rule TTP_XOR_WriteProcessMemory_b5f7 {
  strings:
    $key_b5f7 = { e2 85 [2] d0 a7 [2] d6 92 [2] f8 92 [2] c7 8e }

  condition:
    any of them
}