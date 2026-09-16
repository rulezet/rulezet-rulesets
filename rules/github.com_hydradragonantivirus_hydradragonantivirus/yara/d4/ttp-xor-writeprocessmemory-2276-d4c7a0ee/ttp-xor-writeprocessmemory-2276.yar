rule TTP_XOR_WriteProcessMemory_2276 {
  strings:
    $key_2276 = { 75 04 [2] 47 26 [2] 41 13 [2] 6f 13 [2] 50 0f }

  condition:
    any of them
}