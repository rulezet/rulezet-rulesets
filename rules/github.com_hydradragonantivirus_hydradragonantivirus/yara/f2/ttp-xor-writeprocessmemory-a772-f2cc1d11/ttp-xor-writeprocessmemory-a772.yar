rule TTP_XOR_WriteProcessMemory_a772 {
  strings:
    $key_a772 = { f0 00 [2] c2 22 [2] c4 17 [2] ea 17 [2] d5 0b }

  condition:
    any of them
}