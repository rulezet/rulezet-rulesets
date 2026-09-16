rule TTP_XOR_WriteProcessMemory_b412 {
  strings:
    $key_b412 = { e3 60 [2] d1 42 [2] d7 77 [2] f9 77 [2] c6 6b }

  condition:
    any of them
}