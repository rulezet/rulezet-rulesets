rule TTP_XOR_WriteProcessMemory_1d51 {
  strings:
    $key_1d51 = { 4a 23 [2] 78 01 [2] 7e 34 [2] 50 34 [2] 6f 28 }

  condition:
    any of them
}