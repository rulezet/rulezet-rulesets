rule TTP_XOR_WriteProcessMemory_3af7 {
  strings:
    $key_3af7 = { 6d 85 [2] 5f a7 [2] 59 92 [2] 77 92 [2] 48 8e }

  condition:
    any of them
}