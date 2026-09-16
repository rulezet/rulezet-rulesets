rule TTP_XOR_WriteProcessMemory_8afc {
  strings:
    $key_8afc = { dd 8e [2] ef ac [2] e9 99 [2] c7 99 [2] f8 85 }

  condition:
    any of them
}