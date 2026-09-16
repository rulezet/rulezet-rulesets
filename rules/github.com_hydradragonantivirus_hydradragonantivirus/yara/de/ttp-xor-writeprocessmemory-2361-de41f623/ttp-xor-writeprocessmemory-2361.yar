rule TTP_XOR_WriteProcessMemory_2361 {
  strings:
    $key_2361 = { 74 13 [2] 46 31 [2] 40 04 [2] 6e 04 [2] 51 18 }

  condition:
    any of them
}