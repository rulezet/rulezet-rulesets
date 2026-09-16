rule TTP_XOR_WriteProcessMemory_18ad {
  strings:
    $key_18ad = { 4f df [2] 7d fd [2] 7b c8 [2] 55 c8 [2] 6a d4 }

  condition:
    any of them
}