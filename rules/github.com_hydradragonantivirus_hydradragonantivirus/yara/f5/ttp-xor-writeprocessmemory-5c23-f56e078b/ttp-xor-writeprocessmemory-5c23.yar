rule TTP_XOR_WriteProcessMemory_5c23 {
  strings:
    $key_5c23 = { 0b 51 [2] 39 73 [2] 3f 46 [2] 11 46 [2] 2e 5a }

  condition:
    any of them
}