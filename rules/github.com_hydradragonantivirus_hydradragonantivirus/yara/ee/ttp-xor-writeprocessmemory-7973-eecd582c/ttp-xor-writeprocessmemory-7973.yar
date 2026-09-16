rule TTP_XOR_WriteProcessMemory_7973 {
  strings:
    $key_7973 = { 2e 01 [2] 1c 23 [2] 1a 16 [2] 34 16 [2] 0b 0a }

  condition:
    any of them
}