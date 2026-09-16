rule TTP_XOR_WriteProcessMemory_57e4 {
  strings:
    $key_57e4 = { 00 96 [2] 32 b4 [2] 34 81 [2] 1a 81 [2] 25 9d }

  condition:
    any of them
}