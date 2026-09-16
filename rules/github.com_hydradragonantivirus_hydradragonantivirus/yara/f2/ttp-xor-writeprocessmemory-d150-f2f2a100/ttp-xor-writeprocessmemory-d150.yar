rule TTP_XOR_WriteProcessMemory_d150 {
  strings:
    $key_d150 = { 86 22 [2] b4 00 [2] b2 35 [2] 9c 35 [2] a3 29 }

  condition:
    any of them
}