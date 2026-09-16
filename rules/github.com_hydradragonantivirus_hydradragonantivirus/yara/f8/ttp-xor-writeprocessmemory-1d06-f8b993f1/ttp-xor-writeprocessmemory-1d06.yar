rule TTP_XOR_WriteProcessMemory_1d06 {
  strings:
    $key_1d06 = { 4a 74 [2] 78 56 [2] 7e 63 [2] 50 63 [2] 6f 7f }

  condition:
    any of them
}