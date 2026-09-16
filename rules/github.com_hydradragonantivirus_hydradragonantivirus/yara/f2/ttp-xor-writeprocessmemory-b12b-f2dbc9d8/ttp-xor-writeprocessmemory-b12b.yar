rule TTP_XOR_WriteProcessMemory_b12b {
  strings:
    $key_b12b = { e6 59 [2] d4 7b [2] d2 4e [2] fc 4e [2] c3 52 }

  condition:
    any of them
}