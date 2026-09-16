rule TTP_XOR_WriteProcessMemory_3657 {
  strings:
    $key_3657 = { 61 25 [2] 53 07 [2] 55 32 [2] 7b 32 [2] 44 2e }

  condition:
    any of them
}