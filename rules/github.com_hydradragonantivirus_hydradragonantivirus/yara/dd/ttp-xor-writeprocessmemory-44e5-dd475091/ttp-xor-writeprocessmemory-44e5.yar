rule TTP_XOR_WriteProcessMemory_44e5 {
  strings:
    $key_44e5 = { 13 97 [2] 21 b5 [2] 27 80 [2] 09 80 [2] 36 9c }

  condition:
    any of them
}