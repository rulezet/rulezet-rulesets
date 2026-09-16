rule TTP_XOR_WriteProcessMemory_a4b2 {
  strings:
    $key_a4b2 = { f3 c0 [2] c1 e2 [2] c7 d7 [2] e9 d7 [2] d6 cb }

  condition:
    any of them
}