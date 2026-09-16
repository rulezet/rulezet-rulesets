rule TTP_XOR_WriteProcessMemory_a572 {
  strings:
    $key_a572 = { f2 00 [2] c0 22 [2] c6 17 [2] e8 17 [2] d7 0b }

  condition:
    any of them
}