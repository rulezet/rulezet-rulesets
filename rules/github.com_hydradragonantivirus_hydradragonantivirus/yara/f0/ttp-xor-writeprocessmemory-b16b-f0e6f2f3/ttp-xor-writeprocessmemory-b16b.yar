rule TTP_XOR_WriteProcessMemory_b16b {
  strings:
    $key_b16b = { e6 19 [2] d4 3b [2] d2 0e [2] fc 0e [2] c3 12 }

  condition:
    any of them
}