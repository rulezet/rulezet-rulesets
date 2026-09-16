rule TTP_XOR_WriteProcessMemory_a4ec {
  strings:
    $key_a4ec = { f3 9e [2] c1 bc [2] c7 89 [2] e9 89 [2] d6 95 }

  condition:
    any of them
}