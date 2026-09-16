rule TTP_XOR_WriteProcessMemory_5c73 {
  strings:
    $key_5c73 = { 0b 01 [2] 39 23 [2] 3f 16 [2] 11 16 [2] 2e 0a }

  condition:
    any of them
}