rule TTP_XOR_WriteProcessMemory_4ba6 {
  strings:
    $key_4ba6 = { 1c d4 [2] 2e f6 [2] 28 c3 [2] 06 c3 [2] 39 df }

  condition:
    any of them
}