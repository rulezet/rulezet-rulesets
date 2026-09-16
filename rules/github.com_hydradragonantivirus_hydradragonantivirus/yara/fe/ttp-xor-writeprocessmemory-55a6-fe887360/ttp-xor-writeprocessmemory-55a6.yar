rule TTP_XOR_WriteProcessMemory_55a6 {
  strings:
    $key_55a6 = { 02 d4 [2] 30 f6 [2] 36 c3 [2] 18 c3 [2] 27 df }

  condition:
    any of them
}