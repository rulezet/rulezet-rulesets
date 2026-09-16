rule TTP_XOR_WriteProcessMemory_6657 {
  strings:
    $key_6657 = { 31 25 [2] 03 07 [2] 05 32 [2] 2b 32 [2] 14 2e }

  condition:
    any of them
}