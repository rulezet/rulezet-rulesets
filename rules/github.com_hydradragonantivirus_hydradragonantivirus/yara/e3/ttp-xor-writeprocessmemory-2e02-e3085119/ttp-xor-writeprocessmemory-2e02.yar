rule TTP_XOR_WriteProcessMemory_2e02 {
  strings:
    $key_2e02 = { 79 70 [2] 4b 52 [2] 4d 67 [2] 63 67 [2] 5c 7b }

  condition:
    any of them
}