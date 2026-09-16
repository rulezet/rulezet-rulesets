rule TTP_XOR_WriteProcessMemory_4442 {
  strings:
    $key_4442 = { 13 30 [2] 21 12 [2] 27 27 [2] 09 27 [2] 36 3b }

  condition:
    any of them
}