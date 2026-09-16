rule TTP_XOR_WriteProcessMemory_b2c3 {
  strings:
    $key_b2c3 = { e5 b1 [2] d7 93 [2] d1 a6 [2] ff a6 [2] c0 ba }

  condition:
    any of them
}