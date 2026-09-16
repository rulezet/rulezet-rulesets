rule TTP_XOR_WriteProcessMemory_47ad {
  strings:
    $key_47ad = { 10 df [2] 22 fd [2] 24 c8 [2] 0a c8 [2] 35 d4 }

  condition:
    any of them
}