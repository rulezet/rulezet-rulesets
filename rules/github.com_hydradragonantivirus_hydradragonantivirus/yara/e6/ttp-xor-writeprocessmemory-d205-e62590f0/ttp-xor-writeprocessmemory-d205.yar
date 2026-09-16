rule TTP_XOR_WriteProcessMemory_d205 {
  strings:
    $key_d205 = { 85 77 [2] b7 55 [2] b1 60 [2] 9f 60 [2] a0 7c }

  condition:
    any of them
}