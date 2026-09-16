rule TTP_XOR_WriteProcessMemory_c105 {
  strings:
    $key_c105 = { 96 77 [2] a4 55 [2] a2 60 [2] 8c 60 [2] b3 7c }

  condition:
    any of them
}