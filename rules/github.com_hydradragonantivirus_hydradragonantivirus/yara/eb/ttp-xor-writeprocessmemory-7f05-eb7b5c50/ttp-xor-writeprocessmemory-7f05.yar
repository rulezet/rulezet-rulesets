rule TTP_XOR_WriteProcessMemory_7f05 {
  strings:
    $key_7f05 = { 28 77 [2] 1a 55 [2] 1c 60 [2] 32 60 [2] 0d 7c }

  condition:
    any of them
}