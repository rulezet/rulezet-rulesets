rule TTP_XOR_WriteProcessMemory_35ad {
  strings:
    $key_35ad = { 62 df [2] 50 fd [2] 56 c8 [2] 78 c8 [2] 47 d4 }

  condition:
    any of them
}