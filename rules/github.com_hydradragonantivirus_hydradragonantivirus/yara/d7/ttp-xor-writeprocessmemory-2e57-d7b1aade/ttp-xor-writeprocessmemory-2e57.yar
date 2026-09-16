rule TTP_XOR_WriteProcessMemory_2e57 {
  strings:
    $key_2e57 = { 79 25 [2] 4b 07 [2] 4d 32 [2] 63 32 [2] 5c 2e }

  condition:
    any of them
}