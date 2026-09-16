rule TTP_XOR_WriteProcessMemory_b77c {
  strings:
    $key_b77c = { e0 0e [2] d2 2c [2] d4 19 [2] fa 19 [2] c5 05 }

  condition:
    any of them
}