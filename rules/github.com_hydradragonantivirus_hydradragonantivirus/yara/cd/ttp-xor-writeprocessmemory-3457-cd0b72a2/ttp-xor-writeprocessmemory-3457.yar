rule TTP_XOR_WriteProcessMemory_3457 {
  strings:
    $key_3457 = { 63 25 [2] 51 07 [2] 57 32 [2] 79 32 [2] 46 2e }

  condition:
    any of them
}