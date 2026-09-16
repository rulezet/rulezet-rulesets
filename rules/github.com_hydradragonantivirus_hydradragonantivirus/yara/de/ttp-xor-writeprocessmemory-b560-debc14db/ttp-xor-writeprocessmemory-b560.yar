rule TTP_XOR_WriteProcessMemory_b560 {
  strings:
    $key_b560 = { e2 12 [2] d0 30 [2] d6 05 [2] f8 05 [2] c7 19 }

  condition:
    any of them
}