rule TTP_XOR_WriteProcessMemory_a462 {
  strings:
    $key_a462 = { f3 10 [2] c1 32 [2] c7 07 [2] e9 07 [2] d6 1b }

  condition:
    any of them
}