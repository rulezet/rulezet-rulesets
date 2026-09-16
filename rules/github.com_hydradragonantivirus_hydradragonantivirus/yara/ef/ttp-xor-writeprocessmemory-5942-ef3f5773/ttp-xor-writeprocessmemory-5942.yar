rule TTP_XOR_WriteProcessMemory_5942 {
  strings:
    $key_5942 = { 0e 30 [2] 3c 12 [2] 3a 27 [2] 14 27 [2] 2b 3b }

  condition:
    any of them
}