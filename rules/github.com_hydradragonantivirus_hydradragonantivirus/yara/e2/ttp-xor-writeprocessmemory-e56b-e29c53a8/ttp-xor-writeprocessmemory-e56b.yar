rule TTP_XOR_WriteProcessMemory_e56b {
  strings:
    $key_e56b = { b2 19 [2] 80 3b [2] 86 0e [2] a8 0e [2] 97 12 }

  condition:
    any of them
}