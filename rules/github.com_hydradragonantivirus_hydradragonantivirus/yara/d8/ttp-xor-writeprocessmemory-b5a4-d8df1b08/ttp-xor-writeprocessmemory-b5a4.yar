rule TTP_XOR_WriteProcessMemory_b5a4 {
  strings:
    $key_b5a4 = { e2 d6 [2] d0 f4 [2] d6 c1 [2] f8 c1 [2] c7 dd }

  condition:
    any of them
}