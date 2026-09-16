rule TTP_XOR_WriteProcessMemory_5605 {
  strings:
    $key_5605 = { 01 77 [2] 33 55 [2] 35 60 [2] 1b 60 [2] 24 7c }

  condition:
    any of them
}