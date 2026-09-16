rule TTP_XOR_WriteProcessMemory_db65 {
  strings:
    $key_db65 = { 8c 17 [2] be 35 [2] b8 00 [2] 96 00 [2] a9 1c }

  condition:
    any of them
}