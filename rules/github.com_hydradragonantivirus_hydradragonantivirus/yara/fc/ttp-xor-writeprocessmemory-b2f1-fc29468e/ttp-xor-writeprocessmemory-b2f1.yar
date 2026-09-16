rule TTP_XOR_WriteProcessMemory_b2f1 {
  strings:
    $key_b2f1 = { e5 83 [2] d7 a1 [2] d1 94 [2] ff 94 [2] c0 88 }

  condition:
    any of them
}