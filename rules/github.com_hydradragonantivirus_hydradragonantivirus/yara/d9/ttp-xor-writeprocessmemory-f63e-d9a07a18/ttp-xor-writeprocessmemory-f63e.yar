rule TTP_XOR_WriteProcessMemory_f63e {
  strings:
    $key_f63e = { a1 4c [2] 93 6e [2] 95 5b [2] bb 5b [2] 84 47 }

  condition:
    any of them
}