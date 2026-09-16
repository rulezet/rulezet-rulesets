rule TTP_XOR_WriteProcessMemory_83ec {
  strings:
    $key_83ec = { d4 9e [2] e6 bc [2] e0 89 [2] ce 89 [2] f1 95 }

  condition:
    any of them
}