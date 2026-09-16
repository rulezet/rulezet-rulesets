rule TTP_XOR_WriteProcessMemory_b1c0 {
  strings:
    $key_b1c0 = { e6 b2 [2] d4 90 [2] d2 a5 [2] fc a5 [2] c3 b9 }

  condition:
    any of them
}