rule TTP_XOR_WriteProcessMemory_82ec {
  strings:
    $key_82ec = { d5 9e [2] e7 bc [2] e1 89 [2] cf 89 [2] f0 95 }

  condition:
    any of them
}