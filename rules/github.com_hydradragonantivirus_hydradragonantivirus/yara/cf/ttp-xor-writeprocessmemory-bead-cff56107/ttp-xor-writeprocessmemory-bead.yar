rule TTP_XOR_WriteProcessMemory_bead {
  strings:
    $key_bead = { e9 df [2] db fd [2] dd c8 [2] f3 c8 [2] cc d4 }

  condition:
    any of them
}