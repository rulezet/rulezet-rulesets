rule TTP_XOR_WriteProcessMemory_b26b {
  strings:
    $key_b26b = { e5 19 [2] d7 3b [2] d1 0e [2] ff 0e [2] c0 12 }

  condition:
    any of them
}