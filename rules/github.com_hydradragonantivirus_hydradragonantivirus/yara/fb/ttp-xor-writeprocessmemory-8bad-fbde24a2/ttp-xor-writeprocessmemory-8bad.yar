rule TTP_XOR_WriteProcessMemory_8bad {
  strings:
    $key_8bad = { dc df [2] ee fd [2] e8 c8 [2] c6 c8 [2] f9 d4 }

  condition:
    any of them
}