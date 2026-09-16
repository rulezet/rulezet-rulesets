rule TTP_XOR_WriteProcessMemory_30f0 {
  strings:
    $key_30f0 = { 67 82 [2] 55 a0 [2] 53 95 [2] 7d 95 [2] 42 89 }

  condition:
    any of them
}