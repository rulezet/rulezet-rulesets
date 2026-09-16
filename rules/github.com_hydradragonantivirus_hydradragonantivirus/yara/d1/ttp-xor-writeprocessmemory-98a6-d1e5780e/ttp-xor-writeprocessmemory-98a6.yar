rule TTP_XOR_WriteProcessMemory_98a6 {
  strings:
    $key_98a6 = { cf d4 [2] fd f6 [2] fb c3 [2] d5 c3 [2] ea df }

  condition:
    any of them
}