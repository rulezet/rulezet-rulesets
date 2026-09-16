rule TTP_XOR_WriteProcessMemory_10a6 {
  strings:
    $key_10a6 = { 47 d4 [2] 75 f6 [2] 73 c3 [2] 5d c3 [2] 62 df }

  condition:
    any of them
}