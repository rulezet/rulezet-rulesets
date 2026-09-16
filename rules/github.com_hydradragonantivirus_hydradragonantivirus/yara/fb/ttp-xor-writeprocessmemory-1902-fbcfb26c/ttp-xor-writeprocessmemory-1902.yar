rule TTP_XOR_WriteProcessMemory_1902 {
  strings:
    $key_1902 = { 4e 70 [2] 7c 52 [2] 7a 67 [2] 54 67 [2] 6b 7b }

  condition:
    any of them
}