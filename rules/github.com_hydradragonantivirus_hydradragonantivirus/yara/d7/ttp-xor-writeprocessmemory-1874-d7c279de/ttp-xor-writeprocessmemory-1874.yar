rule TTP_XOR_WriteProcessMemory_1874 {
  strings:
    $key_1874 = { 4f 06 [2] 7d 24 [2] 7b 11 [2] 55 11 [2] 6a 0d }

  condition:
    any of them
}