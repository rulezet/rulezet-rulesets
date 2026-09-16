rule TTP_XOR_WriteProcessMemory_2242 {
  strings:
    $key_2242 = { 75 30 [2] 47 12 [2] 41 27 [2] 6f 27 [2] 50 3b }

  condition:
    any of them
}