rule TTP_XOR_WriteProcessMemory_d505 {
  strings:
    $key_d505 = { 82 77 [2] b0 55 [2] b6 60 [2] 98 60 [2] a7 7c }

  condition:
    any of them
}