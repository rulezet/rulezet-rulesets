rule TTP_XOR_WriteProcessMemory_b480 {
  strings:
    $key_b480 = { e3 f2 [2] d1 d0 [2] d7 e5 [2] f9 e5 [2] c6 f9 }

  condition:
    any of them
}