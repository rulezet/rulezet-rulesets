rule TTP_XOR_WriteProcessMemory_b7c3 {
  strings:
    $key_b7c3 = { e0 b1 [2] d2 93 [2] d4 a6 [2] fa a6 [2] c5 ba }

  condition:
    any of them
}