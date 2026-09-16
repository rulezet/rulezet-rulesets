rule TTP_XOR_WriteProcessMemory_3816 {
  strings:
    $key_3816 = { 6f 64 [2] 5d 46 [2] 5b 73 [2] 75 73 [2] 4a 6f }

  condition:
    any of them
}