rule TTP_XOR_WriteProcessMemory_e50b {
  strings:
    $key_e50b = { b2 79 [2] 80 5b [2] 86 6e [2] a8 6e [2] 97 72 }

  condition:
    any of them
}