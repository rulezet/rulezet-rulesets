rule TTP_XOR_WriteProcessMemory_4302 {
  strings:
    $key_4302 = { 14 70 [2] 26 52 [2] 20 67 [2] 0e 67 [2] 31 7b }

  condition:
    any of them
}