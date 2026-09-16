rule TTP_XOR_WriteProcessMemory_b34b {
  strings:
    $key_b34b = { e4 39 [2] d6 1b [2] d0 2e [2] fe 2e [2] c1 32 }

  condition:
    any of them
}