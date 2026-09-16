rule TTP_XOR_WriteProcessMemory_72ad {
  strings:
    $key_72ad = { 25 df [2] 17 fd [2] 11 c8 [2] 3f c8 [2] 00 d4 }

  condition:
    any of them
}