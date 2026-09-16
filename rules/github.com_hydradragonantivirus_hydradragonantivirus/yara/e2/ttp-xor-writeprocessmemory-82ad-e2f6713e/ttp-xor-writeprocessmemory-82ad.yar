rule TTP_XOR_WriteProcessMemory_82ad {
  strings:
    $key_82ad = { d5 df [2] e7 fd [2] e1 c8 [2] cf c8 [2] f0 d4 }

  condition:
    any of them
}