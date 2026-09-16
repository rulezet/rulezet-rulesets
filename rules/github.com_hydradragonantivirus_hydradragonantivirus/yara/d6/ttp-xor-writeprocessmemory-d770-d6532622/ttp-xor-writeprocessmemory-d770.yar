rule TTP_XOR_WriteProcessMemory_d770 {
  strings:
    $key_d770 = { 80 02 [2] b2 20 [2] b4 15 [2] 9a 15 [2] a5 09 }

  condition:
    any of them
}