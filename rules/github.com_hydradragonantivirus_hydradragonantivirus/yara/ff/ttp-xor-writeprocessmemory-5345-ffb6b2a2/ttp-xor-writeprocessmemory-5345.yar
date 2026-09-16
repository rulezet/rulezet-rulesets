rule TTP_XOR_WriteProcessMemory_5345 {
  strings:
    $key_5345 = { 04 37 [2] 36 15 [2] 30 20 [2] 1e 20 [2] 21 3c }

  condition:
    any of them
}