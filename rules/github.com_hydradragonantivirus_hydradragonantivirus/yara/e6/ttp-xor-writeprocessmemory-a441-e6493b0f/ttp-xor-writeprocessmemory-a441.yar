rule TTP_XOR_WriteProcessMemory_a441 {
  strings:
    $key_a441 = { f3 33 [2] c1 11 [2] c7 24 [2] e9 24 [2] d6 38 }

  condition:
    any of them
}