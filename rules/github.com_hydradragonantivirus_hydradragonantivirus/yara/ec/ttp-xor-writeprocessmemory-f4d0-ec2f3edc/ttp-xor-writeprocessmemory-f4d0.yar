rule TTP_XOR_WriteProcessMemory_f4d0 {
  strings:
    $key_f4d0 = { a3 a2 [2] 91 80 [2] 97 b5 [2] b9 b5 [2] 86 a9 }

  condition:
    any of them
}