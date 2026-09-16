rule TTP_XOR_WriteProcessMemory_1af7 {
  strings:
    $key_1af7 = { 4d 85 [2] 7f a7 [2] 79 92 [2] 57 92 [2] 68 8e }

  condition:
    any of them
}