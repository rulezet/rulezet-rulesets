rule TTP_XOR_WriteProcessMemory_b707 {
  strings:
    $key_b707 = { e0 75 [2] d2 57 [2] d4 62 [2] fa 62 [2] c5 7e }

  condition:
    any of them
}