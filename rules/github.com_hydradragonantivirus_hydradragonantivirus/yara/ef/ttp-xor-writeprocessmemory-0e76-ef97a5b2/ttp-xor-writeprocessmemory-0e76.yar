rule TTP_XOR_WriteProcessMemory_0e76 {
  strings:
    $key_0e76 = { 59 04 [2] 6b 26 [2] 6d 13 [2] 43 13 [2] 7c 0f }

  condition:
    any of them
}