rule TTP_XOR_WriteProcessMemory_2076 {
  strings:
    $key_2076 = { 77 04 [2] 45 26 [2] 43 13 [2] 6d 13 [2] 52 0f }

  condition:
    any of them
}