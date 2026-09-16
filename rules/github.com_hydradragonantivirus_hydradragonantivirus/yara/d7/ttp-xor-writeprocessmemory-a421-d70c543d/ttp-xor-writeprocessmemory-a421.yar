rule TTP_XOR_WriteProcessMemory_a421 {
  strings:
    $key_a421 = { f3 53 [2] c1 71 [2] c7 44 [2] e9 44 [2] d6 58 }

  condition:
    any of them
}