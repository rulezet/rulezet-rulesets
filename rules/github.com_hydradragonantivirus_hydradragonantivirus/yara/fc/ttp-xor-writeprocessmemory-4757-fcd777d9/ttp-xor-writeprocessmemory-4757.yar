rule TTP_XOR_WriteProcessMemory_4757 {
  strings:
    $key_4757 = { 10 25 [2] 22 07 [2] 24 32 [2] 0a 32 [2] 35 2e }

  condition:
    any of them
}