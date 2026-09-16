rule TTP_XOR_WriteProcessMemory_f491 {
  strings:
    $key_f491 = { a3 e3 [2] 91 c1 [2] 97 f4 [2] b9 f4 [2] 86 e8 }

  condition:
    any of them
}