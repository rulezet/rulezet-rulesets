rule TTP_XOR_WriteProcessMemory_11ad {
  strings:
    $key_11ad = { 46 df [2] 74 fd [2] 72 c8 [2] 5c c8 [2] 63 d4 }

  condition:
    any of them
}