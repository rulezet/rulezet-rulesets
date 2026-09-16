rule TTP_XOR_WriteProcessMemory_3043 {
  strings:
    $key_3043 = { 67 31 [2] 55 13 [2] 53 26 [2] 7d 26 [2] 42 3a }

  condition:
    any of them
}