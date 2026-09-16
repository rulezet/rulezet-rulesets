rule TTP_XOR_WriteProcessMemory_f4b4 {
  strings:
    $key_f4b4 = { a3 c6 [2] 91 e4 [2] 97 d1 [2] b9 d1 [2] 86 cd }

  condition:
    any of them
}