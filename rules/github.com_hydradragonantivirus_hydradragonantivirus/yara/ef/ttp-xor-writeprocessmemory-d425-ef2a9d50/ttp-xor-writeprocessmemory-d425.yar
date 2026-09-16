rule TTP_XOR_WriteProcessMemory_d425 {
  strings:
    $key_d425 = { 83 57 [2] b1 75 [2] b7 40 [2] 99 40 [2] a6 5c }

  condition:
    any of them
}