rule TTP_XOR_WriteProcessMemory_6505 {
  strings:
    $key_6505 = { 32 77 [2] 00 55 [2] 06 60 [2] 28 60 [2] 17 7c }

  condition:
    any of them
}