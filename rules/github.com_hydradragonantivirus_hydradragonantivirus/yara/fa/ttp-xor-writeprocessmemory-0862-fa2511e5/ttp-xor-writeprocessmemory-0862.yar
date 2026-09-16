rule TTP_XOR_WriteProcessMemory_0862 {
  strings:
    $key_0862 = { 5f 10 [2] 6d 32 [2] 6b 07 [2] 45 07 [2] 7a 1b }

  condition:
    any of them
}