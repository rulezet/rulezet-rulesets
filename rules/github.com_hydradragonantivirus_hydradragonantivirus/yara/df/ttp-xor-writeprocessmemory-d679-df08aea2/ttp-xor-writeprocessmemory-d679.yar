rule TTP_XOR_WriteProcessMemory_d679 {
  strings:
    $key_d679 = { 81 0b [2] b3 29 [2] b5 1c [2] 9b 1c [2] a4 00 }

  condition:
    any of them
}