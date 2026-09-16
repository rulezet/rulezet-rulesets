rule TTP_XOR_WriteProcessMemory_98a3 {
  strings:
    $key_98a3 = { cf d1 [2] fd f3 [2] fb c6 [2] d5 c6 [2] ea da }

  condition:
    any of them
}