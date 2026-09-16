rule TTP_XOR_WriteProcessMemory_5b77 {
  strings:
    $key_5b77 = { 0c 05 [2] 3e 27 [2] 38 12 [2] 16 12 [2] 29 0e }

  condition:
    any of them
}