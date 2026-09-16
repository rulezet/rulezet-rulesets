rule TTP_XOR_WriteProcessMemory_f294 {
  strings:
    $key_f294 = { a5 e6 [2] 97 c4 [2] 91 f1 [2] bf f1 [2] 80 ed }

  condition:
    any of them
}