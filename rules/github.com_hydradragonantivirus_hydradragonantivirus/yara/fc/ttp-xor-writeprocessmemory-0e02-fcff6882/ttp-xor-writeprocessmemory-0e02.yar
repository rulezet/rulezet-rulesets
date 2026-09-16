rule TTP_XOR_WriteProcessMemory_0e02 {
  strings:
    $key_0e02 = { 59 70 [2] 6b 52 [2] 6d 67 [2] 43 67 [2] 7c 7b }

  condition:
    any of them
}