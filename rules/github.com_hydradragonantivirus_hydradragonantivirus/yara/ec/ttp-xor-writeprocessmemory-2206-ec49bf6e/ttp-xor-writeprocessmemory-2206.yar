rule TTP_XOR_WriteProcessMemory_2206 {
  strings:
    $key_2206 = { 75 74 [2] 47 56 [2] 41 63 [2] 6f 63 [2] 50 7f }

  condition:
    any of them
}