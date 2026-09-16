rule TTP_XOR_WriteProcessMemory_4325 {
  strings:
    $key_4325 = { 14 57 [2] 26 75 [2] 20 40 [2] 0e 40 [2] 31 5c }

  condition:
    any of them
}