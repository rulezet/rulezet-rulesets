rule TTP_XOR_WriteProcessMemory_b73d {
  strings:
    $key_b73d = { e0 4f [2] d2 6d [2] d4 58 [2] fa 58 [2] c5 44 }

  condition:
    any of them
}