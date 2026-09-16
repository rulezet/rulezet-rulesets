rule TTP_XOR_WriteProcessMemory_ede5 {
  strings:
    $key_ede5 = { ba 97 [2] 88 b5 [2] 8e 80 [2] a0 80 [2] 9f 9c }

  condition:
    any of them
}