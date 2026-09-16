rule TTP_XOR_WriteProcessMemory_50e5 {
  strings:
    $key_50e5 = { 07 97 [2] 35 b5 [2] 33 80 [2] 1d 80 [2] 22 9c }

  condition:
    any of them
}