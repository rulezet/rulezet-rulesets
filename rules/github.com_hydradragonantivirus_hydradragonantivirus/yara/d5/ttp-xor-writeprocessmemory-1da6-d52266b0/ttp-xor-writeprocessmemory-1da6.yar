rule TTP_XOR_WriteProcessMemory_1da6 {
  strings:
    $key_1da6 = { 4a d4 [2] 78 f6 [2] 7e c3 [2] 50 c3 [2] 6f df }

  condition:
    any of them
}