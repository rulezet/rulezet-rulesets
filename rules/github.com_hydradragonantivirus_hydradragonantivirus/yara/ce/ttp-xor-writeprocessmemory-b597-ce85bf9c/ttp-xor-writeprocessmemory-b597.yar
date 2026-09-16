rule TTP_XOR_WriteProcessMemory_b597 {
  strings:
    $key_b597 = { e2 e5 [2] d0 c7 [2] d6 f2 [2] f8 f2 [2] c7 ee }

  condition:
    any of them
}