rule TTP_XOR_WriteProcessMemory_7775 {
  strings:
    $key_7775 = { 20 07 [2] 12 25 [2] 14 10 [2] 3a 10 [2] 05 0c }

  condition:
    any of them
}