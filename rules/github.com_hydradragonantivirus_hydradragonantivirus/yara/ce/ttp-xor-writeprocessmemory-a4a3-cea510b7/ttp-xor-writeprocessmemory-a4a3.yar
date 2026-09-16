rule TTP_XOR_WriteProcessMemory_a4a3 {
  strings:
    $key_a4a3 = { f3 d1 [2] c1 f3 [2] c7 c6 [2] e9 c6 [2] d6 da }

  condition:
    any of them
}