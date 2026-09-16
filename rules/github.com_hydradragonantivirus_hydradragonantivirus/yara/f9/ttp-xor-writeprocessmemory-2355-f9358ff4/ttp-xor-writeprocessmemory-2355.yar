rule TTP_XOR_WriteProcessMemory_2355 {
  strings:
    $key_2355 = { 74 27 [2] 46 05 [2] 40 30 [2] 6e 30 [2] 51 2c }

  condition:
    any of them
}