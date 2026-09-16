rule TTP_XOR_WriteProcessMemory_6057 {
  strings:
    $key_6057 = { 37 25 [2] 05 07 [2] 03 32 [2] 2d 32 [2] 12 2e }

  condition:
    any of them
}