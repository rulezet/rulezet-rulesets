rule TTP_XOR_WriteProcessMemory_b150 {
  strings:
    $key_b150 = { e6 22 [2] d4 00 [2] d2 35 [2] fc 35 [2] c3 29 }

  condition:
    any of them
}