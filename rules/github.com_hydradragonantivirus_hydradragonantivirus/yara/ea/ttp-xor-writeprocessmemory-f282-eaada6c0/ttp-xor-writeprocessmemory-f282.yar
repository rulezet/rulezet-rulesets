rule TTP_XOR_WriteProcessMemory_f282 {
  strings:
    $key_f282 = { a5 f0 [2] 97 d2 [2] 91 e7 [2] bf e7 [2] 80 fb }

  condition:
    any of them
}