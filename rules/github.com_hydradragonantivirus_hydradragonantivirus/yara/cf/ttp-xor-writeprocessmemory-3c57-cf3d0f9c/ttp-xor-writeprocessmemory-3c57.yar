rule TTP_XOR_WriteProcessMemory_3c57 {
  strings:
    $key_3c57 = { 6b 25 [2] 59 07 [2] 5f 32 [2] 71 32 [2] 4e 2e }

  condition:
    any of them
}