rule TTP_XOR_WriteProcessMemory_4402 {
  strings:
    $key_4402 = { 13 70 [2] 21 52 [2] 27 67 [2] 09 67 [2] 36 7b }

  condition:
    any of them
}