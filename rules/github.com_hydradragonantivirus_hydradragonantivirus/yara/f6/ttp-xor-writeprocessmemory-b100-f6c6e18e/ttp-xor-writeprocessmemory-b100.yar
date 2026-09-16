rule TTP_XOR_WriteProcessMemory_b100 {
  strings:
    $key_b100 = { e6 72 [2] d4 50 [2] d2 65 [2] fc 65 [2] c3 79 }

  condition:
    any of them
}