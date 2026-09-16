rule TTP_XOR_WriteProcessMemory_d671 {
  strings:
    $key_d671 = { 81 03 [2] b3 21 [2] b5 14 [2] 9b 14 [2] a4 08 }

  condition:
    any of them
}