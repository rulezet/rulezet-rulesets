rule TTP_XOR_WriteProcessMemory_b460 {
  strings:
    $key_b460 = { e3 12 [2] d1 30 [2] d7 05 [2] f9 05 [2] c6 19 }

  condition:
    any of them
}