rule TTP_XOR_WriteProcessMemory_a5ec {
  strings:
    $key_a5ec = { f2 9e [2] c0 bc [2] c6 89 [2] e8 89 [2] d7 95 }

  condition:
    any of them
}