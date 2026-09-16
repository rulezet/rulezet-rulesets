rule TTP_XOR_WriteProcessMemory_6205 {
  strings:
    $key_6205 = { 35 77 [2] 07 55 [2] 01 60 [2] 2f 60 [2] 10 7c }

  condition:
    any of them
}