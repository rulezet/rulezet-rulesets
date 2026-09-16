rule TTP_XOR_WriteProcessMemory_2373 {
  strings:
    $key_2373 = { 74 01 [2] 46 23 [2] 40 16 [2] 6e 16 [2] 51 0a }

  condition:
    any of them
}