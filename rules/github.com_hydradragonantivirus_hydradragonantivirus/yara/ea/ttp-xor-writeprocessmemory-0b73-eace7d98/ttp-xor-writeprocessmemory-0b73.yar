rule TTP_XOR_WriteProcessMemory_0b73 {
  strings:
    $key_0b73 = { 5c 01 [2] 6e 23 [2] 68 16 [2] 46 16 [2] 79 0a }

  condition:
    any of them
}