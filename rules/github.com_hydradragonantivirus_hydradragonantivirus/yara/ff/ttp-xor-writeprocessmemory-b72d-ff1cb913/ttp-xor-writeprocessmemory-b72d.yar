rule TTP_XOR_WriteProcessMemory_b72d {
  strings:
    $key_b72d = { e0 5f [2] d2 7d [2] d4 48 [2] fa 48 [2] c5 54 }

  condition:
    any of them
}