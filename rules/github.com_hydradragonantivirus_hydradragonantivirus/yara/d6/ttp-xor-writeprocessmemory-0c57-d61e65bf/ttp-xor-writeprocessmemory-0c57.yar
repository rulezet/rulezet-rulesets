rule TTP_XOR_WriteProcessMemory_0c57 {
  strings:
    $key_0c57 = { 5b 25 [2] 69 07 [2] 6f 32 [2] 41 32 [2] 7e 2e }

  condition:
    any of them
}