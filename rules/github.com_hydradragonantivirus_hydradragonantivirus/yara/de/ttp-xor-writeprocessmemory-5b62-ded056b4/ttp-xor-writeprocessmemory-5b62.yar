rule TTP_XOR_WriteProcessMemory_5b62 {
  strings:
    $key_5b62 = { 0c 10 [2] 3e 32 [2] 38 07 [2] 16 07 [2] 29 1b }

  condition:
    any of them
}