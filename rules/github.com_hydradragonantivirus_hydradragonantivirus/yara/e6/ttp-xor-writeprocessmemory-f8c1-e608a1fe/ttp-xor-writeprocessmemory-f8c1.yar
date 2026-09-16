rule TTP_XOR_WriteProcessMemory_f8c1 {
  strings:
    $key_f8c1 = { af b3 [2] 9d 91 [2] 9b a4 [2] b5 a4 [2] 8a b8 }

  condition:
    any of them
}