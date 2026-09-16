rule TTP_XOR_WriteProcessMemory_f61c {
  strings:
    $key_f61c = { a1 6e [2] 93 4c [2] 95 79 [2] bb 79 [2] 84 65 }

  condition:
    any of them
}