rule TTP_XOR_WriteProcessMemory_a27b {
  strings:
    $key_a27b = { f5 09 [2] c7 2b [2] c1 1e [2] ef 1e [2] d0 02 }

  condition:
    any of them
}