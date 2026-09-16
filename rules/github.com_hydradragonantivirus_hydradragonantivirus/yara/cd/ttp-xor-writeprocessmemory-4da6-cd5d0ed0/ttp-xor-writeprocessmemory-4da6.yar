rule TTP_XOR_WriteProcessMemory_4da6 {
  strings:
    $key_4da6 = { 1a d4 [2] 28 f6 [2] 2e c3 [2] 00 c3 [2] 3f df }

  condition:
    any of them
}