rule TTP_XOR_WriteProcessMemory_b7f1 {
  strings:
    $key_b7f1 = { e0 83 [2] d2 a1 [2] d4 94 [2] fa 94 [2] c5 88 }

  condition:
    any of them
}