rule TTP_XOR_WriteProcessMemory_aa46 {
  strings:
    $key_aa46 = { fd 34 [2] cf 16 [2] c9 23 [2] e7 23 [2] d8 3f }

  condition:
    any of them
}