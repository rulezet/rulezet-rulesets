rule TTP_XOR_WriteProcessMemory_3ec5 {
  strings:
    $key_3ec5 = { 69 b7 [2] 5b 95 [2] 5d a0 [2] 73 a0 [2] 4c bc }

  condition:
    any of them
}