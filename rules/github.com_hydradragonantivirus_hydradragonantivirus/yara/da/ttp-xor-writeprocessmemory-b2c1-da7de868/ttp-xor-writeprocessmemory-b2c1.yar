rule TTP_XOR_WriteProcessMemory_b2c1 {
  strings:
    $key_b2c1 = { e5 b3 [2] d7 91 [2] d1 a4 [2] ff a4 [2] c0 b8 }

  condition:
    any of them
}