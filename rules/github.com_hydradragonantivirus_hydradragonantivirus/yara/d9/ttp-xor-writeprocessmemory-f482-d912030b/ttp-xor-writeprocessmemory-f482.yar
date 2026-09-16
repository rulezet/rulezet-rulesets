rule TTP_XOR_WriteProcessMemory_f482 {
  strings:
    $key_f482 = { a3 f0 [2] 91 d2 [2] 97 e7 [2] b9 e7 [2] 86 fb }

  condition:
    any of them
}