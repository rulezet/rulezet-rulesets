rule TTP_XOR_WriteProcessMemory_56ad {
  strings:
    $key_56ad = { 01 df [2] 33 fd [2] 35 c8 [2] 1b c8 [2] 24 d4 }

  condition:
    any of them
}