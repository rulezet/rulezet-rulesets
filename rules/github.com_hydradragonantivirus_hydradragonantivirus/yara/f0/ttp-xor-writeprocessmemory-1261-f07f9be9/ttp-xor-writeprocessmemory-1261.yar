rule TTP_XOR_WriteProcessMemory_1261 {
  strings:
    $key_1261 = { 45 13 [2] 77 31 [2] 71 04 [2] 5f 04 [2] 60 18 }

  condition:
    any of them
}