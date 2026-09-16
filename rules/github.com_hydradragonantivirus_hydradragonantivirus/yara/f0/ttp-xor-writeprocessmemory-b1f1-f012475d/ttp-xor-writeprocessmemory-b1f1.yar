rule TTP_XOR_WriteProcessMemory_b1f1 {
  strings:
    $key_b1f1 = { e6 83 [2] d4 a1 [2] d2 94 [2] fc 94 [2] c3 88 }

  condition:
    any of them
}