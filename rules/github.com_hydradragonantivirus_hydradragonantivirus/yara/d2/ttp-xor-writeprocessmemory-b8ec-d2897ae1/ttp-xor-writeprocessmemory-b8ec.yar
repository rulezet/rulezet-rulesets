rule TTP_XOR_WriteProcessMemory_b8ec {
  strings:
    $key_b8ec = { ef 9e [2] dd bc [2] db 89 [2] f5 89 [2] ca 95 }

  condition:
    any of them
}