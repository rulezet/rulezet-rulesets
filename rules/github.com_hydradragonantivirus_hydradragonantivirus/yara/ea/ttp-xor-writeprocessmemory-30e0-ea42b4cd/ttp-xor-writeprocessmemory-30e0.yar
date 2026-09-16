rule TTP_XOR_WriteProcessMemory_30e0 {
  strings:
    $key_30e0 = { 67 92 [2] 55 b0 [2] 53 85 [2] 7d 85 [2] 42 99 }

  condition:
    any of them
}