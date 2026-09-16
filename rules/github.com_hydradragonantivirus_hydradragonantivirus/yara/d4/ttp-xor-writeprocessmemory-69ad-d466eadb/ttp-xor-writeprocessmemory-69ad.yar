rule TTP_XOR_WriteProcessMemory_69ad {
  strings:
    $key_69ad = { 3e df [2] 0c fd [2] 0a c8 [2] 24 c8 [2] 1b d4 }

  condition:
    any of them
}