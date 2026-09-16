rule TTP_XOR_WriteProcessMemory_2d76 {
  strings:
    $key_2d76 = { 7a 04 [2] 48 26 [2] 4e 13 [2] 60 13 [2] 5f 0f }

  condition:
    any of them
}