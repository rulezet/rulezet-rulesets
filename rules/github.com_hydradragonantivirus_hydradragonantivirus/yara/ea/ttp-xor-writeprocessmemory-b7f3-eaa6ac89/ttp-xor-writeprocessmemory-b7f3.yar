rule TTP_XOR_WriteProcessMemory_b7f3 {
  strings:
    $key_b7f3 = { e0 81 [2] d2 a3 [2] d4 96 [2] fa 96 [2] c5 8a }

  condition:
    any of them
}