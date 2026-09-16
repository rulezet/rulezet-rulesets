rule TTP_XOR_WriteProcessMemory_7573 {
  strings:
    $key_7573 = { 22 01 [2] 10 23 [2] 16 16 [2] 38 16 [2] 07 0a }

  condition:
    any of them
}