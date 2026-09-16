rule TTP_XOR_WriteProcessMemory_3c55 {
  strings:
    $key_3c55 = { 6b 27 [2] 59 05 [2] 5f 30 [2] 71 30 [2] 4e 2c }

  condition:
    any of them
}