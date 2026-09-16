rule TTP_XOR_WriteProcessMemory_4d77 {
  strings:
    $key_4d77 = { 1a 05 [2] 28 27 [2] 2e 12 [2] 00 12 [2] 3f 0e }

  condition:
    any of them
}