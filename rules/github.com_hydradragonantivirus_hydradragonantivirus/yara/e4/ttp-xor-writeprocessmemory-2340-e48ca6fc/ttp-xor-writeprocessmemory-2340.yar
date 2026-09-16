rule TTP_XOR_WriteProcessMemory_2340 {
  strings:
    $key_2340 = { 74 32 [2] 46 10 [2] 40 25 [2] 6e 25 [2] 51 39 }

  condition:
    any of them
}