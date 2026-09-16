rule TTP_XOR_WriteProcessMemory_f67e {
  strings:
    $key_f67e = { a1 0c [2] 93 2e [2] 95 1b [2] bb 1b [2] 84 07 }

  condition:
    any of them
}