rule TTP_XOR_WriteProcessMemory_2af2 {
  strings:
    $key_2af2 = { 7d 80 [2] 4f a2 [2] 49 97 [2] 67 97 [2] 58 8b }

  condition:
    any of them
}