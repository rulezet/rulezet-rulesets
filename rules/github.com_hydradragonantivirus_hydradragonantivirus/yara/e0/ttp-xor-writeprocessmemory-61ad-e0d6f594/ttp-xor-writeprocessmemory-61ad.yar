rule TTP_XOR_WriteProcessMemory_61ad {
  strings:
    $key_61ad = { 36 df [2] 04 fd [2] 02 c8 [2] 2c c8 [2] 13 d4 }

  condition:
    any of them
}