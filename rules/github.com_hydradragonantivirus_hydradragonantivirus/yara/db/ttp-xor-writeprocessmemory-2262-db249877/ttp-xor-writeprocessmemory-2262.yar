rule TTP_XOR_WriteProcessMemory_2262 {
  strings:
    $key_2262 = { 75 10 [2] 47 32 [2] 41 07 [2] 6f 07 [2] 50 1b }

  condition:
    any of them
}