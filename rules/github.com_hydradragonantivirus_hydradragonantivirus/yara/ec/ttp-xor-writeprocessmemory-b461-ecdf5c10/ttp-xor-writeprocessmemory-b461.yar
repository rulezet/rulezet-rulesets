rule TTP_XOR_WriteProcessMemory_b461 {
  strings:
    $key_b461 = { e3 13 [2] d1 31 [2] d7 04 [2] f9 04 [2] c6 18 }

  condition:
    any of them
}