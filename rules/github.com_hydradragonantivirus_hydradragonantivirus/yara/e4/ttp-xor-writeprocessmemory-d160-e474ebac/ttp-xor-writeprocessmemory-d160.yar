rule TTP_XOR_WriteProcessMemory_d160 {
  strings:
    $key_d160 = { 86 12 [2] b4 30 [2] b2 05 [2] 9c 05 [2] a3 19 }

  condition:
    any of them
}