rule TTP_XOR_WriteProcessMemory_6605 {
  strings:
    $key_6605 = { 31 77 [2] 03 55 [2] 05 60 [2] 2b 60 [2] 14 7c }

  condition:
    any of them
}