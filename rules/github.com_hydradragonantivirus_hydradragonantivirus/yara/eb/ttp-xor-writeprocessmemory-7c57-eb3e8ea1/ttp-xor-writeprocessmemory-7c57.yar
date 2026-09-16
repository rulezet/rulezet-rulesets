rule TTP_XOR_WriteProcessMemory_7c57 {
  strings:
    $key_7c57 = { 2b 25 [2] 19 07 [2] 1f 32 [2] 31 32 [2] 0e 2e }

  condition:
    any of them
}