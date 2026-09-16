rule TTP_XOR_WriteProcessMemory_5c62 {
  strings:
    $key_5c62 = { 0b 10 [2] 39 32 [2] 3f 07 [2] 11 07 [2] 2e 1b }

  condition:
    any of them
}