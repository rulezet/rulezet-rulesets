rule TTP_XOR_WriteProcessMemory_b27b {
  strings:
    $key_b27b = { e5 09 [2] d7 2b [2] d1 1e [2] ff 1e [2] c0 02 }

  condition:
    any of them
}