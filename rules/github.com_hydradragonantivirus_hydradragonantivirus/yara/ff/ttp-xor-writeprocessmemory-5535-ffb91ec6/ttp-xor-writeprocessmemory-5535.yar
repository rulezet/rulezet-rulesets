rule TTP_XOR_WriteProcessMemory_5535 {
  strings:
    $key_5535 = { 02 47 [2] 30 65 [2] 36 50 [2] 18 50 [2] 27 4c }

  condition:
    any of them
}