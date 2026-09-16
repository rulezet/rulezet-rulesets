rule TTP_XOR_WriteProcessMemory_f288 {
  strings:
    $key_f288 = { a5 fa [2] 97 d8 [2] 91 ed [2] bf ed [2] 80 f1 }

  condition:
    any of them
}