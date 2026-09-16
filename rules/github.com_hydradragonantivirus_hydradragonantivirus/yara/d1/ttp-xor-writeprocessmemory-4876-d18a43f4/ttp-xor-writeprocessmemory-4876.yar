rule TTP_XOR_WriteProcessMemory_4876 {
  strings:
    $key_4876 = { 1f 04 [2] 2d 26 [2] 2b 13 [2] 05 13 [2] 3a 0f }

  condition:
    any of them
}