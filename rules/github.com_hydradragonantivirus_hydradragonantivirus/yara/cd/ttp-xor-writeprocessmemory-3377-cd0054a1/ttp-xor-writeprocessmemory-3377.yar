rule TTP_XOR_WriteProcessMemory_3377 {
  strings:
    $key_3377 = { 64 05 [2] 56 27 [2] 50 12 [2] 7e 12 [2] 41 0e }

  condition:
    any of them
}