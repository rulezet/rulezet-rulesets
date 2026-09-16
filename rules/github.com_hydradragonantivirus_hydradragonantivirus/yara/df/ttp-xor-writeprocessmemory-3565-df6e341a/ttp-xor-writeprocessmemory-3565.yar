rule TTP_XOR_WriteProcessMemory_3565 {
  strings:
    $key_3565 = { 62 17 [2] 50 35 [2] 56 00 [2] 78 00 [2] 47 1c }

  condition:
    any of them
}