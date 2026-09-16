rule TTP_XOR_WriteProcessMemory_5ba6 {
  strings:
    $key_5ba6 = { 0c d4 [2] 3e f6 [2] 38 c3 [2] 16 c3 [2] 29 df }

  condition:
    any of them
}