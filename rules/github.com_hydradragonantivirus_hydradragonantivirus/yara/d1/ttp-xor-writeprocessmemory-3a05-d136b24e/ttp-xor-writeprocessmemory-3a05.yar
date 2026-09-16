rule TTP_XOR_WriteProcessMemory_3a05 {
  strings:
    $key_3a05 = { 6d 77 [2] 5f 55 [2] 59 60 [2] 77 60 [2] 48 7c }

  condition:
    any of them
}