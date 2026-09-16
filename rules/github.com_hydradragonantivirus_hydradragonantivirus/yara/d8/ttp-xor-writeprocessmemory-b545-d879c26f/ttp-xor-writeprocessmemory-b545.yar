rule TTP_XOR_WriteProcessMemory_b545 {
  strings:
    $key_b545 = { e2 37 [2] d0 15 [2] d6 20 [2] f8 20 [2] c7 3c }

  condition:
    any of them
}