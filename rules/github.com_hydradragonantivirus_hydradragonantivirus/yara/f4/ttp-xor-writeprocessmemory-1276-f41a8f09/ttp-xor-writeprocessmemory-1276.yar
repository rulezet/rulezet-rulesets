rule TTP_XOR_WriteProcessMemory_1276 {
  strings:
    $key_1276 = { 45 04 [2] 77 26 [2] 71 13 [2] 5f 13 [2] 60 0f }

  condition:
    any of them
}