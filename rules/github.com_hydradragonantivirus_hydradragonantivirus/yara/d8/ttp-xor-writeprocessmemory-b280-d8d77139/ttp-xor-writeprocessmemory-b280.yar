rule TTP_XOR_WriteProcessMemory_b280 {
  strings:
    $key_b280 = { e5 f2 [2] d7 d0 [2] d1 e5 [2] ff e5 [2] c0 f9 }

  condition:
    any of them
}