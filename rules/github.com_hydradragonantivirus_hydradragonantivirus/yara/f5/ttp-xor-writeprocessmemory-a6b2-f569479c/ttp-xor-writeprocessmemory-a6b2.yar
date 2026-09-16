rule TTP_XOR_WriteProcessMemory_a6b2 {
  strings:
    $key_a6b2 = { f1 c0 [2] c3 e2 [2] c5 d7 [2] eb d7 [2] d4 cb }

  condition:
    any of them
}