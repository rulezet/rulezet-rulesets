rule TTP_XOR_WriteProcessMemory_5a05 {
  strings:
    $key_5a05 = { 0d 77 [2] 3f 55 [2] 39 60 [2] 17 60 [2] 28 7c }

  condition:
    any of them
}