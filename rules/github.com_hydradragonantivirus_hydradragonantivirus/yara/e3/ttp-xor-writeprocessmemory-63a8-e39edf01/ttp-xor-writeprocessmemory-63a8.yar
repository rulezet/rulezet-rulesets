rule TTP_XOR_WriteProcessMemory_63a8 {
  strings:
    $key_63a8 = { 34 da [2] 06 f8 [2] 00 cd [2] 2e cd [2] 11 d1 }

  condition:
    any of them
}