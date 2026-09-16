rule TTP_XOR_WriteProcessMemory_3002 {
  strings:
    $key_3002 = { 67 70 [2] 55 52 [2] 53 67 [2] 7d 67 [2] 42 7b }

  condition:
    any of them
}