rule TTP_XOR_WriteProcessMemory_b7e7 {
  strings:
    $key_b7e7 = { e0 95 [2] d2 b7 [2] d4 82 [2] fa 82 [2] c5 9e }

  condition:
    any of them
}