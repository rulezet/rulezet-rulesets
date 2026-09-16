rule TTP_XOR_WriteProcessMemory_6377 {
  strings:
    $key_6377 = { 34 05 [2] 06 27 [2] 00 12 [2] 2e 12 [2] 11 0e }

  condition:
    any of them
}