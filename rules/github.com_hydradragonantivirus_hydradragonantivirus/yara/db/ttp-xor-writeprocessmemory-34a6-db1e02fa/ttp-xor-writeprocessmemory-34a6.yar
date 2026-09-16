rule TTP_XOR_WriteProcessMemory_34a6 {
  strings:
    $key_34a6 = { 63 d4 [2] 51 f6 [2] 57 c3 [2] 79 c3 [2] 46 df }

  condition:
    any of them
}