rule TTP_XOR_WriteProcessMemory_0705 {
  strings:
    $key_0705 = { 50 77 [2] 62 55 [2] 64 60 [2] 4a 60 [2] 75 7c }

  condition:
    any of them
}