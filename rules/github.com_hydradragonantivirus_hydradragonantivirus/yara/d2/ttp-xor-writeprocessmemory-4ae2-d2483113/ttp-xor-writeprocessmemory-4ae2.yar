rule TTP_XOR_WriteProcessMemory_4ae2 {
  strings:
    $key_4ae2 = { 1d 90 [2] 2f b2 [2] 29 87 [2] 07 87 [2] 38 9b }

  condition:
    any of them
}