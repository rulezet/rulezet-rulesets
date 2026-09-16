rule TTP_XOR_WriteProcessMemory_5002 {
  strings:
    $key_5002 = { 07 70 [2] 35 52 [2] 33 67 [2] 1d 67 [2] 22 7b }

  condition:
    any of them
}