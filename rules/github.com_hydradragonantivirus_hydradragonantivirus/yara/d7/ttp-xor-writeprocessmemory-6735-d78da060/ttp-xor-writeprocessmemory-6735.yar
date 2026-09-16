rule TTP_XOR_WriteProcessMemory_6735 {
  strings:
    $key_6735 = { 30 47 [2] 02 65 [2] 04 50 [2] 2a 50 [2] 15 4c }

  condition:
    any of them
}