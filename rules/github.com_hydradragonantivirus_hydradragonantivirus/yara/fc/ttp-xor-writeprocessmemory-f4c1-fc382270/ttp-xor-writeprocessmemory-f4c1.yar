rule TTP_XOR_WriteProcessMemory_f4c1 {
  strings:
    $key_f4c1 = { a3 b3 [2] 91 91 [2] 97 a4 [2] b9 a4 [2] 86 b8 }

  condition:
    any of them
}