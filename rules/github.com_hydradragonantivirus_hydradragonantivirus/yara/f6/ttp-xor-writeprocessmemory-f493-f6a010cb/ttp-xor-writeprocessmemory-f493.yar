rule TTP_XOR_WriteProcessMemory_f493 {
  strings:
    $key_f493 = { a3 e1 [2] 91 c3 [2] 97 f6 [2] b9 f6 [2] 86 ea }

  condition:
    any of them
}