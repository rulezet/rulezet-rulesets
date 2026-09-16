rule TTP_XOR_WriteProcessMemory_f65c {
  strings:
    $key_f65c = { a1 2e [2] 93 0c [2] 95 39 [2] bb 39 [2] 84 25 }

  condition:
    any of them
}