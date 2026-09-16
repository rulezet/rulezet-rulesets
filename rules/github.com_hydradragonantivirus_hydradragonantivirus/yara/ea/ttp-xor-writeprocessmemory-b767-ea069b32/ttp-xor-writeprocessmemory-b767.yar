rule TTP_XOR_WriteProcessMemory_b767 {
  strings:
    $key_b767 = { e0 15 [2] d2 37 [2] d4 02 [2] fa 02 [2] c5 1e }

  condition:
    any of them
}