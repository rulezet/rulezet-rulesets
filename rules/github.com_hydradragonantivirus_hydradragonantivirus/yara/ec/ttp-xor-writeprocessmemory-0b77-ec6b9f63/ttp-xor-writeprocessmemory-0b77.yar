rule TTP_XOR_WriteProcessMemory_0b77 {
  strings:
    $key_0b77 = { 5c 05 [2] 6e 27 [2] 68 12 [2] 46 12 [2] 79 0e }

  condition:
    any of them
}