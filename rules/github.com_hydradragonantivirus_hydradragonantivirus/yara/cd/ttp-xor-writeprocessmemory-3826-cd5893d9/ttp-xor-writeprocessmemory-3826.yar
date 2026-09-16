rule TTP_XOR_WriteProcessMemory_3826 {
  strings:
    $key_3826 = { 6f 54 [2] 5d 76 [2] 5b 43 [2] 75 43 [2] 4a 5f }

  condition:
    any of them
}