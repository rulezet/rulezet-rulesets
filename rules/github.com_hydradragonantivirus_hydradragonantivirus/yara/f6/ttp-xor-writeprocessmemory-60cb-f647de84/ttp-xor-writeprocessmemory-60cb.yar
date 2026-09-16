rule TTP_XOR_WriteProcessMemory_60cb {
  strings:
    $key_60cb = { 37 b9 [2] 05 9b [2] 03 ae [2] 2d ae [2] 12 b2 }

  condition:
    any of them
}