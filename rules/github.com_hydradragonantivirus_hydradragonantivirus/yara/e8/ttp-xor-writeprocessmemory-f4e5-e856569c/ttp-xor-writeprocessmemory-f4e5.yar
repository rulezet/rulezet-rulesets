rule TTP_XOR_WriteProcessMemory_f4e5 {
  strings:
    $key_f4e5 = { a3 97 [2] 91 b5 [2] 97 80 [2] b9 80 [2] 86 9c }

  condition:
    any of them
}