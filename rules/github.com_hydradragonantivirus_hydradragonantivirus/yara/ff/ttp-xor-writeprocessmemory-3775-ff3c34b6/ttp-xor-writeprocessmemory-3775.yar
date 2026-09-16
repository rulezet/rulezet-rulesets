rule TTP_XOR_WriteProcessMemory_3775 {
  strings:
    $key_3775 = { 60 07 [2] 52 25 [2] 54 10 [2] 7a 10 [2] 45 0c }

  condition:
    any of them
}