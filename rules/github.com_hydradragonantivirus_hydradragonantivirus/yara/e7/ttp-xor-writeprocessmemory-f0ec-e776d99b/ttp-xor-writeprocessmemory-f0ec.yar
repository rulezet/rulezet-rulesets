rule TTP_XOR_WriteProcessMemory_f0ec {
  strings:
    $key_f0ec = { a7 9e [2] 95 bc [2] 93 89 [2] bd 89 [2] 82 95 }

  condition:
    any of them
}