rule TTP_XOR_WriteProcessMemory_a3a3 {
  strings:
    $key_a3a3 = { f4 d1 [2] c6 f3 [2] c0 c6 [2] ee c6 [2] d1 da }

  condition:
    any of them
}