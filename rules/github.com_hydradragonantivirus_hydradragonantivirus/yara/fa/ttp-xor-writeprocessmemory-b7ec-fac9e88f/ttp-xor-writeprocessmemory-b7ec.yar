rule TTP_XOR_WriteProcessMemory_b7ec {
  strings:
    $key_b7ec = { e0 9e [2] d2 bc [2] d4 89 [2] fa 89 [2] c5 95 }

  condition:
    any of them
}