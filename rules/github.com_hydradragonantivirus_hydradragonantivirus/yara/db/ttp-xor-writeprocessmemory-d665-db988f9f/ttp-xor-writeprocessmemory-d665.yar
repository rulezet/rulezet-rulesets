rule TTP_XOR_WriteProcessMemory_d665 {
  strings:
    $key_d665 = { 81 17 [2] b3 35 [2] b5 00 [2] 9b 00 [2] a4 1c }

  condition:
    any of them
}