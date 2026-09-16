rule TTP_XOR_WriteProcessMemory_a70b {
  strings:
    $key_a70b = { f0 79 [2] c2 5b [2] c4 6e [2] ea 6e [2] d5 72 }

  condition:
    any of them
}