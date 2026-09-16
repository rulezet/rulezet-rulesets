rule TTP_XOR_WriteProcessMemory_71f2 {
  strings:
    $key_71f2 = { 26 80 [2] 14 a2 [2] 12 97 [2] 3c 97 [2] 03 8b }

  condition:
    any of them
}