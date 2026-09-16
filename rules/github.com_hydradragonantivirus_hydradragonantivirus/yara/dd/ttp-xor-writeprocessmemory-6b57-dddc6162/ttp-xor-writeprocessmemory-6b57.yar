rule TTP_XOR_WriteProcessMemory_6b57 {
  strings:
    $key_6b57 = { 3c 25 [2] 0e 07 [2] 08 32 [2] 26 32 [2] 19 2e }

  condition:
    any of them
}