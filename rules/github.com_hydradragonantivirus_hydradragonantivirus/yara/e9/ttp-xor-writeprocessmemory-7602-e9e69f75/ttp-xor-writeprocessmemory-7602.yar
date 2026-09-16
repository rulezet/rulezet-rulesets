rule TTP_XOR_WriteProcessMemory_7602 {
  strings:
    $key_7602 = { 21 70 [2] 13 52 [2] 15 67 [2] 3b 67 [2] 04 7b }

  condition:
    any of them
}