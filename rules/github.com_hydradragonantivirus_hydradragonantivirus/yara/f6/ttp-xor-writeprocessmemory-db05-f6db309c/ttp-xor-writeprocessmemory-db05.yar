rule TTP_XOR_WriteProcessMemory_db05 {
  strings:
    $key_db05 = { 8c 77 [2] be 55 [2] b8 60 [2] 96 60 [2] a9 7c }

  condition:
    any of them
}