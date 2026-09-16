rule TTP_XOR_WriteProcessMemory_1f05 {
  strings:
    $key_1f05 = { 48 77 [2] 7a 55 [2] 7c 60 [2] 52 60 [2] 6d 7c }

  condition:
    any of them
}