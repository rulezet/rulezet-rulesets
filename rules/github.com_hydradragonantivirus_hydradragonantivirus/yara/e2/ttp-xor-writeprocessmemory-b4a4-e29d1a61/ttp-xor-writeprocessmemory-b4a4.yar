rule TTP_XOR_WriteProcessMemory_b4a4 {
  strings:
    $key_b4a4 = { e3 d6 [2] d1 f4 [2] d7 c1 [2] f9 c1 [2] c6 dd }

  condition:
    any of them
}