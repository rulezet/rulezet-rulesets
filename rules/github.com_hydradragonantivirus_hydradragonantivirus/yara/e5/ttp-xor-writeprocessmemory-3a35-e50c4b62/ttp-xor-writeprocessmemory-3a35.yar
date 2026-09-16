rule TTP_XOR_WriteProcessMemory_3a35 {
  strings:
    $key_3a35 = { 6d 47 [2] 5f 65 [2] 59 50 [2] 77 50 [2] 48 4c }

  condition:
    any of them
}