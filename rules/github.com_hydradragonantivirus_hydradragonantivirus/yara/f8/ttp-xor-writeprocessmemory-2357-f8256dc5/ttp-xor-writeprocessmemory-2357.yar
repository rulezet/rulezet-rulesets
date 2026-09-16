rule TTP_XOR_WriteProcessMemory_2357 {
  strings:
    $key_2357 = { 74 25 [2] 46 07 [2] 40 32 [2] 6e 32 [2] 51 2e }

  condition:
    any of them
}