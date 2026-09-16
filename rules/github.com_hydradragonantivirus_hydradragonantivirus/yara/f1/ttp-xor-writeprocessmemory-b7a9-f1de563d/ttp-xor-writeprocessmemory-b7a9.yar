rule TTP_XOR_WriteProcessMemory_b7a9 {
  strings:
    $key_b7a9 = { e0 db [2] d2 f9 [2] d4 cc [2] fa cc [2] c5 d0 }

  condition:
    any of them
}