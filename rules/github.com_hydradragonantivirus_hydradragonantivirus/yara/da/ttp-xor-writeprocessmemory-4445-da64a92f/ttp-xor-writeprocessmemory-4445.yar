rule TTP_XOR_WriteProcessMemory_4445 {
  strings:
    $key_4445 = { 13 37 [2] 21 15 [2] 27 20 [2] 09 20 [2] 36 3c }

  condition:
    any of them
}