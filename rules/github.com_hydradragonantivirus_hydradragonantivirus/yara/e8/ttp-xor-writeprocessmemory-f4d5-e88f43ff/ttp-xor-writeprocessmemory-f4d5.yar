rule TTP_XOR_WriteProcessMemory_f4d5 {
  strings:
    $key_f4d5 = { a3 a7 [2] 91 85 [2] 97 b0 [2] b9 b0 [2] 86 ac }

  condition:
    any of them
}