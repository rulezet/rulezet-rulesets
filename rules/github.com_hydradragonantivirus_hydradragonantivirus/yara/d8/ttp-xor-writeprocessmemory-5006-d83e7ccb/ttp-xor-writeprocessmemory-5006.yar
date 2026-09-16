rule TTP_XOR_WriteProcessMemory_5006 {
  strings:
    $key_5006 = { 07 74 [2] 35 56 [2] 33 63 [2] 1d 63 [2] 22 7f }

  condition:
    any of them
}