rule TTP_XOR_WriteProcessMemory_0a05 {
  strings:
    $key_0a05 = { 5d 77 [2] 6f 55 [2] 69 60 [2] 47 60 [2] 78 7c }

  condition:
    any of them
}