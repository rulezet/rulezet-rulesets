rule TTP_XOR_WriteProcessMemory_a5a3 {
  strings:
    $key_a5a3 = { f2 d1 [2] c0 f3 [2] c6 c6 [2] e8 c6 [2] d7 da }

  condition:
    any of them
}