rule TTP_XOR_WriteProcessMemory_3977 {
  strings:
    $key_3977 = { 6e 05 [2] 5c 27 [2] 5a 12 [2] 74 12 [2] 4b 0e }

  condition:
    any of them
}