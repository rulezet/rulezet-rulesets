rule TTP_XOR_WriteProcessMemory_1465 {
  strings:
    $key_1465 = { 43 17 [2] 71 35 [2] 77 00 [2] 59 00 [2] 66 1c }

  condition:
    any of them
}