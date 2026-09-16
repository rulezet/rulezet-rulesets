rule TTP_XOR_WriteProcessMemory_2266 {
  strings:
    $key_2266 = { 75 14 [2] 47 36 [2] 41 03 [2] 6f 03 [2] 50 1f }

  condition:
    any of them
}