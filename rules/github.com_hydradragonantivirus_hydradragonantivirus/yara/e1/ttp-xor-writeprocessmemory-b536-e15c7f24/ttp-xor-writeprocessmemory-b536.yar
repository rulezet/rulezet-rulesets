rule TTP_XOR_WriteProcessMemory_b536 {
  strings:
    $key_b536 = { e2 44 [2] d0 66 [2] d6 53 [2] f8 53 [2] c7 4f }

  condition:
    any of them
}