rule TTP_XOR_WriteProcessMemory_2377 {
  strings:
    $key_2377 = { 74 05 [2] 46 27 [2] 40 12 [2] 6e 12 [2] 51 0e }

  condition:
    any of them
}