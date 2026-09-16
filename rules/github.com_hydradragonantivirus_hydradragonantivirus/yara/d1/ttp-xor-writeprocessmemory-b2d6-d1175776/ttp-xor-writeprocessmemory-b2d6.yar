rule TTP_XOR_WriteProcessMemory_b2d6 {
  strings:
    $key_b2d6 = { e5 a4 [2] d7 86 [2] d1 b3 [2] ff b3 [2] c0 af }

  condition:
    any of them
}