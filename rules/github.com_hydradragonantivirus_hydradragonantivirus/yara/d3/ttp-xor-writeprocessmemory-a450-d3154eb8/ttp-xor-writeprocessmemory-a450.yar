rule TTP_XOR_WriteProcessMemory_a450 {
  strings:
    $key_a450 = { f3 22 [2] c1 00 [2] c7 35 [2] e9 35 [2] d6 29 }

  condition:
    any of them
}