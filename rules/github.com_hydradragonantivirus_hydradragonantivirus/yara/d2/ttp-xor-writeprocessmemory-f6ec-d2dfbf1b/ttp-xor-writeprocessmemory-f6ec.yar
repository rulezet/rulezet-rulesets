rule TTP_XOR_WriteProcessMemory_f6ec {
  strings:
    $key_f6ec = { a1 9e [2] 93 bc [2] 95 89 [2] bb 89 [2] 84 95 }

  condition:
    any of them
}