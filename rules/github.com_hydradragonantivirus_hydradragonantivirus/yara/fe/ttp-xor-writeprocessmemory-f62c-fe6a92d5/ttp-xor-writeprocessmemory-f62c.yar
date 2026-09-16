rule TTP_XOR_WriteProcessMemory_f62c {
  strings:
    $key_f62c = { a1 5e [2] 93 7c [2] 95 49 [2] bb 49 [2] 84 55 }

  condition:
    any of them
}