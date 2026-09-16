rule TTP_XOR_WriteProcessMemory_bbad {
  strings:
    $key_bbad = { ec df [2] de fd [2] d8 c8 [2] f6 c8 [2] c9 d4 }

  condition:
    any of them
}