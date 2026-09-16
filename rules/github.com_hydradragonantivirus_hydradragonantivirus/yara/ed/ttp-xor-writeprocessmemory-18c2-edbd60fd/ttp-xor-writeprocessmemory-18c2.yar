rule TTP_XOR_WriteProcessMemory_18c2 {
  strings:
    $key_18c2 = { 4f b0 [2] 7d 92 [2] 7b a7 [2] 55 a7 [2] 6a bb }

  condition:
    any of them
}