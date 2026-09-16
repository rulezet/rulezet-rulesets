rule TTP_XOR_WriteProcessMemory_12e5 {
  strings:
    $key_12e5 = { 45 97 [2] 77 b5 [2] 71 80 [2] 5f 80 [2] 60 9c }

  condition:
    any of them
}