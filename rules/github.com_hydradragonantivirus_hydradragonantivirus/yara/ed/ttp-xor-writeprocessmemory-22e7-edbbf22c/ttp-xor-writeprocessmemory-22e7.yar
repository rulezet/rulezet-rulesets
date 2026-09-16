rule TTP_XOR_WriteProcessMemory_22e7 {
  strings:
    $key_22e7 = { 75 95 [2] 47 b7 [2] 41 82 [2] 6f 82 [2] 50 9e }

  condition:
    any of them
}