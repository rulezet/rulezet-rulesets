rule TTP_XOR_WriteProcessMemory_d105 {
  strings:
    $key_d105 = { 86 77 [2] b4 55 [2] b2 60 [2] 9c 60 [2] a3 7c }

  condition:
    any of them
}