rule TTP_XOR_WriteProcessMemory_2af7 {
  strings:
    $key_2af7 = { 7d 85 [2] 4f a7 [2] 49 92 [2] 67 92 [2] 58 8e }

  condition:
    any of them
}