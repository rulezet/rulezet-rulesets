rule TTP_XOR_WriteProcessMemory_93ad {
  strings:
    $key_93ad = { c4 df [2] f6 fd [2] f0 c8 [2] de c8 [2] e1 d4 }

  condition:
    any of them
}