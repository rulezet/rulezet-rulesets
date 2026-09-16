rule TTP_XOR_WriteProcessMemory_a765 {
  strings:
    $key_a765 = { f0 17 [2] c2 35 [2] c4 00 [2] ea 00 [2] d5 1c }

  condition:
    any of them
}