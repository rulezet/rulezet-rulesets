rule TTP_XOR_WriteProcessMemory_2364 {
  strings:
    $key_2364 = { 74 16 [2] 46 34 [2] 40 01 [2] 6e 01 [2] 51 1d }

  condition:
    any of them
}