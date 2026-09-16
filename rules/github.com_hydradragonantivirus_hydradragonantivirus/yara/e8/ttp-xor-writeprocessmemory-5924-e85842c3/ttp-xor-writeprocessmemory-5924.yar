rule TTP_XOR_WriteProcessMemory_5924 {
  strings:
    $key_5924 = { 0e 56 [2] 3c 74 [2] 3a 41 [2] 14 41 [2] 2b 5d }

  condition:
    any of them
}