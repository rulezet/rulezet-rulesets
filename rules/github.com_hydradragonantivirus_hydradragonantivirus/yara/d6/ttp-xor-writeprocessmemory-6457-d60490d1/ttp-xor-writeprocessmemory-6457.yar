rule TTP_XOR_WriteProcessMemory_6457 {
  strings:
    $key_6457 = { 33 25 [2] 01 07 [2] 07 32 [2] 29 32 [2] 16 2e }

  condition:
    any of them
}