rule TTP_XOR_WriteProcessMemory_a4d9 {
  strings:
    $key_a4d9 = { f3 ab [2] c1 89 [2] c7 bc [2] e9 bc [2] d6 a0 }

  condition:
    any of them
}