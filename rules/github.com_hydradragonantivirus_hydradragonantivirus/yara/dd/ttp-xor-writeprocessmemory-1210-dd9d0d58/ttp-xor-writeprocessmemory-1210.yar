rule TTP_XOR_WriteProcessMemory_1210 {
  strings:
    $key_1210 = { 45 62 [2] 77 40 [2] 71 75 [2] 5f 75 [2] 60 69 }

  condition:
    any of them
}