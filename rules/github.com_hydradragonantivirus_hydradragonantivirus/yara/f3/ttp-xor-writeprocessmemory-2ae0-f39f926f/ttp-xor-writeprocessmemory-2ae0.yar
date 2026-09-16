rule TTP_XOR_WriteProcessMemory_2ae0 {
  strings:
    $key_2ae0 = { 7d 92 [2] 4f b0 [2] 49 85 [2] 67 85 [2] 58 99 }

  condition:
    any of them
}