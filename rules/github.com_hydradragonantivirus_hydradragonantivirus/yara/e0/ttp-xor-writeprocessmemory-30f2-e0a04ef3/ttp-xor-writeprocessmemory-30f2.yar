rule TTP_XOR_WriteProcessMemory_30f2 {
  strings:
    $key_30f2 = { 67 80 [2] 55 a2 [2] 53 97 [2] 7d 97 [2] 42 8b }

  condition:
    any of them
}