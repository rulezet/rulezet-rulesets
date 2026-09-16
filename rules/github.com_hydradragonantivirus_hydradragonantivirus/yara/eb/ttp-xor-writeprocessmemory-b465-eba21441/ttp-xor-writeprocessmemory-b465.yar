rule TTP_XOR_WriteProcessMemory_b465 {
  strings:
    $key_b465 = { e3 17 [2] d1 35 [2] d7 00 [2] f9 00 [2] c6 1c }

  condition:
    any of them
}