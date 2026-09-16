rule TTP_XOR_WriteProcessMemory_4006 {
  strings:
    $key_4006 = { 17 74 [2] 25 56 [2] 23 63 [2] 0d 63 [2] 32 7f }

  condition:
    any of them
}