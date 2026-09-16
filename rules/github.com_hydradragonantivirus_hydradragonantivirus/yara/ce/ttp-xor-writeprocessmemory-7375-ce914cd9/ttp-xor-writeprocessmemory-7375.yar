rule TTP_XOR_WriteProcessMemory_7375 {
  strings:
    $key_7375 = { 24 07 [2] 16 25 [2] 10 10 [2] 3e 10 [2] 01 0c }

  condition:
    any of them
}