rule TTP_XOR_WriteProcessMemory_a54b {
  strings:
    $key_a54b = { f2 39 [2] c0 1b [2] c6 2e [2] e8 2e [2] d7 32 }

  condition:
    any of them
}