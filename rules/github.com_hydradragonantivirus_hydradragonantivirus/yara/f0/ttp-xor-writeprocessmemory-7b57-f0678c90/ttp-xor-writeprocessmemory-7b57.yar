rule TTP_XOR_WriteProcessMemory_7b57 {
  strings:
    $key_7b57 = { 2c 25 [2] 1e 07 [2] 18 32 [2] 36 32 [2] 09 2e }

  condition:
    any of them
}