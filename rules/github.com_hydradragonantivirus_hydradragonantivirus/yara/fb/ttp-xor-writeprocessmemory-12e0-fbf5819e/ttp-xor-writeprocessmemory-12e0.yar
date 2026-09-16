rule TTP_XOR_WriteProcessMemory_12e0 {
  strings:
    $key_12e0 = { 45 92 [2] 77 b0 [2] 71 85 [2] 5f 85 [2] 60 99 }

  condition:
    any of them
}