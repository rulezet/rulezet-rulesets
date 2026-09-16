rule TTP_XOR_WriteProcessMemory_b17b {
  strings:
    $key_b17b = { e6 09 [2] d4 2b [2] d2 1e [2] fc 1e [2] c3 02 }

  condition:
    any of them
}