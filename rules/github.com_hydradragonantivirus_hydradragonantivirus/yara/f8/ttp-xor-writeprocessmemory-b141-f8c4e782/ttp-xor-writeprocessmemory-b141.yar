rule TTP_XOR_WriteProcessMemory_b141 {
  strings:
    $key_b141 = { e6 33 [2] d4 11 [2] d2 24 [2] fc 24 [2] c3 38 }

  condition:
    any of them
}