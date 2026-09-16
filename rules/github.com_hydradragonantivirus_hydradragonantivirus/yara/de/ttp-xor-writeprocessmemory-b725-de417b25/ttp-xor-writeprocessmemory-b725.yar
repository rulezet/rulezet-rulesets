rule TTP_XOR_WriteProcessMemory_b725 {
  strings:
    $key_b725 = { e0 57 [2] d2 75 [2] d4 40 [2] fa 40 [2] c5 5c }

  condition:
    any of them
}