rule TTP_XOR_WriteProcessMemory_5015 {
  strings:
    $key_5015 = { 07 67 [2] 35 45 [2] 33 70 [2] 1d 70 [2] 22 6c }

  condition:
    any of them
}