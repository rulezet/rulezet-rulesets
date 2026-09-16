rule TTP_XOR_WriteProcessMemory_4b62 {
  strings:
    $key_4b62 = { 1c 10 [2] 2e 32 [2] 28 07 [2] 06 07 [2] 39 1b }

  condition:
    any of them
}