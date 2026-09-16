rule TTP_XOR_WriteProcessMemory_f61b {
  strings:
    $key_f61b = { a1 69 [2] 93 4b [2] 95 7e [2] bb 7e [2] 84 62 }

  condition:
    any of them
}