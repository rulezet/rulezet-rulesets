rule TTP_XOR_WriteProcessMemory_1f57 {
  strings:
    $key_1f57 = { 48 25 [2] 7a 07 [2] 7c 32 [2] 52 32 [2] 6d 2e }

  condition:
    any of them
}