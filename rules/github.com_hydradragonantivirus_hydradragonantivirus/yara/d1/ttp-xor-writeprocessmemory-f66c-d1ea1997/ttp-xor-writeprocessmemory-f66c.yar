rule TTP_XOR_WriteProcessMemory_f66c {
  strings:
    $key_f66c = { a1 1e [2] 93 3c [2] 95 09 [2] bb 09 [2] 84 15 }

  condition:
    any of them
}