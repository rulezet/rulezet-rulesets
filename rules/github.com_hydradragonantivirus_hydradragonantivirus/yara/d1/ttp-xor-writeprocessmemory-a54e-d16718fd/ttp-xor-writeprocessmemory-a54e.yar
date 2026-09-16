rule TTP_XOR_WriteProcessMemory_a54e {
  strings:
    $key_a54e = { f2 3c [2] c0 1e [2] c6 2b [2] e8 2b [2] d7 37 }

  condition:
    any of them
}