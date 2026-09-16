rule TTP_XOR_WriteProcessMemory_2352 {
  strings:
    $key_2352 = { 74 20 [2] 46 02 [2] 40 37 [2] 6e 37 [2] 51 2b }

  condition:
    any of them
}