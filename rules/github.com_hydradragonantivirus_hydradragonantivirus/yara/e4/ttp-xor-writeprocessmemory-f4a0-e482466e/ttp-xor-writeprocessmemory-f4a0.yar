rule TTP_XOR_WriteProcessMemory_f4a0 {
  strings:
    $key_f4a0 = { a3 d2 [2] 91 f0 [2] 97 c5 [2] b9 c5 [2] 86 d9 }

  condition:
    any of them
}