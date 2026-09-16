rule TTP_XOR_WriteProcessMemory_8b8c {
  strings:
    $key_8b8c = { dc fe [2] ee dc [2] e8 e9 [2] c6 e9 [2] f9 f5 }

  condition:
    any of them
}