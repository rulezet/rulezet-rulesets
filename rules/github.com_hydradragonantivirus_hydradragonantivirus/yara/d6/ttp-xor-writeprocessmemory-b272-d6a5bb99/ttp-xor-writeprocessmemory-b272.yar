rule TTP_XOR_WriteProcessMemory_b272 {
  strings:
    $key_b272 = { e5 00 [2] d7 22 [2] d1 17 [2] ff 17 [2] c0 0b }

  condition:
    any of them
}