rule TTP_XOR_WriteProcessMemory_2b76 {
  strings:
    $key_2b76 = { 7c 04 [2] 4e 26 [2] 48 13 [2] 66 13 [2] 59 0f }

  condition:
    any of them
}