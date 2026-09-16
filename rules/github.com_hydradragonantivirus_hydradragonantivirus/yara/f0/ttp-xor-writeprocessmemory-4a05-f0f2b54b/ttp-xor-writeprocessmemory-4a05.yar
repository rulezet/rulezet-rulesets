rule TTP_XOR_WriteProcessMemory_4a05 {
  strings:
    $key_4a05 = { 1d 77 [2] 2f 55 [2] 29 60 [2] 07 60 [2] 38 7c }

  condition:
    any of them
}