rule TTP_XOR_WriteProcessMemory_a4e2 {
  strings:
    $key_a4e2 = { f3 90 [2] c1 b2 [2] c7 87 [2] e9 87 [2] d6 9b }

  condition:
    any of them
}