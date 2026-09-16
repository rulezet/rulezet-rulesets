rule TTP_XOR_WriteProcessMemory_1062 {
  strings:
    $key_1062 = { 47 10 [2] 75 32 [2] 73 07 [2] 5d 07 [2] 62 1b }

  condition:
    any of them
}