rule TTP_XOR_WriteProcessMemory_2ba6 {
  strings:
    $key_2ba6 = { 7c d4 [2] 4e f6 [2] 48 c3 [2] 66 c3 [2] 59 df }

  condition:
    any of them
}