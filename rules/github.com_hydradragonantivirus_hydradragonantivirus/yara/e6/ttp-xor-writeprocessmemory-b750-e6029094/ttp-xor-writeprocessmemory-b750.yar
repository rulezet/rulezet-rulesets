rule TTP_XOR_WriteProcessMemory_b750 {
  strings:
    $key_b750 = { e0 22 [2] d2 00 [2] d4 35 [2] fa 35 [2] c5 29 }

  condition:
    any of them
}