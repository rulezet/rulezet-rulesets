rule TTP_XOR_WriteProcessMemory_2d25 {
  strings:
    $key_2d25 = { 7a 57 [2] 48 75 [2] 4e 40 [2] 60 40 [2] 5f 5c }

  condition:
    any of them
}