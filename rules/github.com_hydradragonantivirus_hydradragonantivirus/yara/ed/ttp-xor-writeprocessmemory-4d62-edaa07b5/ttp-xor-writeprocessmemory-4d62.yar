rule TTP_XOR_WriteProcessMemory_4d62 {
  strings:
    $key_4d62 = { 1a 10 [2] 28 32 [2] 2e 07 [2] 00 07 [2] 3f 1b }

  condition:
    any of them
}