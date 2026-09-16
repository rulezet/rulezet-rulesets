rule TTP_XOR_WriteProcessMemory_3746 {
  strings:
    $key_3746 = { 60 34 [2] 52 16 [2] 54 23 [2] 7a 23 [2] 45 3f }

  condition:
    any of them
}