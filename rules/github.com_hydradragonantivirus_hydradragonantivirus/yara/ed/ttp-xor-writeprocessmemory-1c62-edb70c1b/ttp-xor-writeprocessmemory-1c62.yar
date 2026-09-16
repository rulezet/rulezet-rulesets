rule TTP_XOR_WriteProcessMemory_1c62 {
  strings:
    $key_1c62 = { 4b 10 [2] 79 32 [2] 7f 07 [2] 51 07 [2] 6e 1b }

  condition:
    any of them
}