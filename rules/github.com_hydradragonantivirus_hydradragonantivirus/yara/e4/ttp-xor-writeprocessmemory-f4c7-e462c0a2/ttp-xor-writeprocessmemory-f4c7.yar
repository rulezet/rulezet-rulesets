rule TTP_XOR_WriteProcessMemory_f4c7 {
  strings:
    $key_f4c7 = { a3 b5 [2] 91 97 [2] 97 a2 [2] b9 a2 [2] 86 be }

  condition:
    any of them
}