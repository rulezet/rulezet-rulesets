rule TTP_XOR_WriteProcessMemory_3b77 {
  strings:
    $key_3b77 = { 6c 05 [2] 5e 27 [2] 58 12 [2] 76 12 [2] 49 0e }

  condition:
    any of them
}