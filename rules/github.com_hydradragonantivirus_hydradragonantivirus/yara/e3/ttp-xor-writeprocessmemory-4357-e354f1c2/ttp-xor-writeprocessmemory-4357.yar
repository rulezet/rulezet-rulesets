rule TTP_XOR_WriteProcessMemory_4357 {
  strings:
    $key_4357 = { 14 25 [2] 26 07 [2] 20 32 [2] 0e 32 [2] 31 2e }

  condition:
    any of them
}