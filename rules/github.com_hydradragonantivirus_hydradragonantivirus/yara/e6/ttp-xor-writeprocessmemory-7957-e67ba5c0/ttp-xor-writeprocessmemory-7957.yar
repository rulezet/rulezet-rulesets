rule TTP_XOR_WriteProcessMemory_7957 {
  strings:
    $key_7957 = { 2e 25 [2] 1c 07 [2] 1a 32 [2] 34 32 [2] 0b 2e }

  condition:
    any of them
}