rule TTP_XOR_WriteProcessMemory_27e5 {
  strings:
    $key_27e5 = { 70 97 [2] 42 b5 [2] 44 80 [2] 6a 80 [2] 55 9c }

  condition:
    any of them
}