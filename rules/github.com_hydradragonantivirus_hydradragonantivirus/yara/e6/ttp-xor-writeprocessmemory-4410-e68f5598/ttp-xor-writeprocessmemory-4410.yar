rule TTP_XOR_WriteProcessMemory_4410 {
  strings:
    $key_4410 = { 13 62 [2] 21 40 [2] 27 75 [2] 09 75 [2] 36 69 }

  condition:
    any of them
}