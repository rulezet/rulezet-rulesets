rule TTP_XOR_WriteProcessMemory_5657 {
  strings:
    $key_5657 = { 01 25 [2] 33 07 [2] 35 32 [2] 1b 32 [2] 24 2e }

  condition:
    any of them
}