rule TTP_XOR_WriteProcessMemory_3846 {
  strings:
    $key_3846 = { 6f 34 [2] 5d 16 [2] 5b 23 [2] 75 23 [2] 4a 3f }

  condition:
    any of them
}