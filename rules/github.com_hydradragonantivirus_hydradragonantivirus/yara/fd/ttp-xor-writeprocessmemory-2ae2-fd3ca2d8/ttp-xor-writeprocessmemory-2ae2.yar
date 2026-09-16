rule TTP_XOR_WriteProcessMemory_2ae2 {
  strings:
    $key_2ae2 = { 7d 90 [2] 4f b2 [2] 49 87 [2] 67 87 [2] 58 9b }

  condition:
    any of them
}