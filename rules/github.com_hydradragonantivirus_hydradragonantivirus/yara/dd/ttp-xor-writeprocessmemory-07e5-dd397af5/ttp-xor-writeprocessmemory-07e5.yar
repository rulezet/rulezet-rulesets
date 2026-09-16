rule TTP_XOR_WriteProcessMemory_07e5 {
  strings:
    $key_07e5 = { 50 97 [2] 62 b5 [2] 64 80 [2] 4a 80 [2] 75 9c }

  condition:
    any of them
}