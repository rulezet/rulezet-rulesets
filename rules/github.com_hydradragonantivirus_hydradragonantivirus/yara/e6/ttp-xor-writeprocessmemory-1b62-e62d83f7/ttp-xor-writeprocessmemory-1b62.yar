rule TTP_XOR_WriteProcessMemory_1b62 {
  strings:
    $key_1b62 = { 4c 10 [2] 7e 32 [2] 78 07 [2] 56 07 [2] 69 1b }

  condition:
    any of them
}