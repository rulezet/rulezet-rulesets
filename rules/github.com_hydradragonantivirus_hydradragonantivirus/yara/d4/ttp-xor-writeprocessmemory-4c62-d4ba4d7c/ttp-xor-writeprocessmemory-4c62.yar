rule TTP_XOR_WriteProcessMemory_4c62 {
  strings:
    $key_4c62 = { 1b 10 [2] 29 32 [2] 2f 07 [2] 01 07 [2] 3e 1b }

  condition:
    any of them
}