rule TTP_XOR_WriteProcessMemory_3016 {
  strings:
    $key_3016 = { 67 64 [2] 55 46 [2] 53 73 [2] 7d 73 [2] 42 6f }

  condition:
    any of them
}