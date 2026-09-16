rule TTP_XOR_WriteProcessMemory_7642 {
  strings:
    $key_7642 = { 21 30 [2] 13 12 [2] 15 27 [2] 3b 27 [2] 04 3b }

  condition:
    any of them
}