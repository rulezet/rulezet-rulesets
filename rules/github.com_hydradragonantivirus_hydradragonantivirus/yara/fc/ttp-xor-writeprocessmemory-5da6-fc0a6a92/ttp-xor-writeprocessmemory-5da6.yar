rule TTP_XOR_WriteProcessMemory_5da6 {
  strings:
    $key_5da6 = { 0a d4 [2] 38 f6 [2] 3e c3 [2] 10 c3 [2] 2f df }

  condition:
    any of them
}