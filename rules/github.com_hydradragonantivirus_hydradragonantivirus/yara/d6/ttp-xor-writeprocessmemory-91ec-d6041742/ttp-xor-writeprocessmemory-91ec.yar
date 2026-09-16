rule TTP_XOR_WriteProcessMemory_91ec {
  strings:
    $key_91ec = { c6 9e [2] f4 bc [2] f2 89 [2] dc 89 [2] e3 95 }

  condition:
    any of them
}