rule TTP_XOR_WriteProcessMemory_5975 {
  strings:
    $key_5975 = { 0e 07 [2] 3c 25 [2] 3a 10 [2] 14 10 [2] 2b 0c }

  condition:
    any of them
}