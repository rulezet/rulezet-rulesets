rule TTP_XOR_WriteProcessMemory_c505 {
  strings:
    $key_c505 = { 92 77 [2] a0 55 [2] a6 60 [2] 88 60 [2] b7 7c }

  condition:
    any of them
}