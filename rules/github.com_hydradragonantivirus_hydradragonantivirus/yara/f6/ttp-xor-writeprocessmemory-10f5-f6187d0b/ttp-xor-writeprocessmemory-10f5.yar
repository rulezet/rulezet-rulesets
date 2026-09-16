rule TTP_XOR_WriteProcessMemory_10f5 {
  strings:
    $key_10f5 = { 47 87 [2] 75 a5 [2] 73 90 [2] 5d 90 [2] 62 8c }

  condition:
    any of them
}