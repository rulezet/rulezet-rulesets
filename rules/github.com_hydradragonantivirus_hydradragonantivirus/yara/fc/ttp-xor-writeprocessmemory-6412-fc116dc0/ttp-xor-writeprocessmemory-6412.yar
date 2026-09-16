rule TTP_XOR_WriteProcessMemory_6412 {
  strings:
    $key_6412 = { 33 60 [2] 01 42 [2] 07 77 [2] 29 77 [2] 16 6b }

  condition:
    any of them
}