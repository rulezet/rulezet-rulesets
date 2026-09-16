rule TTP_XOR_WriteProcessMemory_b178 {
  strings:
    $key_b178 = { e6 0a [2] d4 28 [2] d2 1d [2] fc 1d [2] c3 01 }

  condition:
    any of them
}