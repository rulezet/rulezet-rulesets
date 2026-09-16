rule TTP_XOR_WriteProcessMemory_1d77 {
  strings:
    $key_1d77 = { 4a 05 [2] 78 27 [2] 7e 12 [2] 50 12 [2] 6f 0e }

  condition:
    any of them
}