rule TTP_XOR_WriteProcessMemory_4957 {
  strings:
    $key_4957 = { 1e 25 [2] 2c 07 [2] 2a 32 [2] 04 32 [2] 3b 2e }

  condition:
    any of them
}