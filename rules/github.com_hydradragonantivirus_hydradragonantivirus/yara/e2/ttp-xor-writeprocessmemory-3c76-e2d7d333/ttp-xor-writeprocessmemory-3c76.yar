rule TTP_XOR_WriteProcessMemory_3c76 {
  strings:
    $key_3c76 = { 6b 04 [2] 59 26 [2] 5f 13 [2] 71 13 [2] 4e 0f }

  condition:
    any of them
}