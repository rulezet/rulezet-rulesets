rule TTP_XOR_WriteProcessMemory_1d73 {
  strings:
    $key_1d73 = { 4a 01 [2] 78 23 [2] 7e 16 [2] 50 16 [2] 6f 0a }

  condition:
    any of them
}