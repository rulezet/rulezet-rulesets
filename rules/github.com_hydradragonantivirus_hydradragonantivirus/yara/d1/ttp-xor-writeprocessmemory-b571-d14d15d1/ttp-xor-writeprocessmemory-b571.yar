rule TTP_XOR_WriteProcessMemory_b571 {
  strings:
    $key_b571 = { e2 03 [2] d0 21 [2] d6 14 [2] f8 14 [2] c7 08 }

  condition:
    any of them
}