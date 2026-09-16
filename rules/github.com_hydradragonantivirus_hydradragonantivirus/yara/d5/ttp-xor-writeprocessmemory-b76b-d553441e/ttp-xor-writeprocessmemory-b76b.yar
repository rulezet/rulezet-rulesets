rule TTP_XOR_WriteProcessMemory_b76b {
  strings:
    $key_b76b = { e0 19 [2] d2 3b [2] d4 0e [2] fa 0e [2] c5 12 }

  condition:
    any of them
}