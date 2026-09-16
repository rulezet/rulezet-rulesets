rule TTP_XOR_WriteProcessMemory_b4a7 {
  strings:
    $key_b4a7 = { e3 d5 [2] d1 f7 [2] d7 c2 [2] f9 c2 [2] c6 de }

  condition:
    any of them
}