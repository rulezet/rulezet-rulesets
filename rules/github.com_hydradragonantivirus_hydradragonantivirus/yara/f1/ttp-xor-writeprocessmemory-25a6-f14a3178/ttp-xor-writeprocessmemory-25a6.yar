rule TTP_XOR_WriteProcessMemory_25a6 {
  strings:
    $key_25a6 = { 72 d4 [2] 40 f6 [2] 46 c3 [2] 68 c3 [2] 57 df }

  condition:
    any of them
}