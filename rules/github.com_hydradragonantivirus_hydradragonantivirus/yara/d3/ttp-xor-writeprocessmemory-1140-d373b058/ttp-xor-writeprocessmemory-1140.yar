rule TTP_XOR_WriteProcessMemory_1140 {
  strings:
    $key_1140 = { 46 32 [2] 74 10 [2] 72 25 [2] 5c 25 [2] 63 39 }

  condition:
    any of them
}