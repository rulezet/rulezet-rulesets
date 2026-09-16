rule TTP_XOR_WriteProcessMemory_e570 {
  strings:
    $key_e570 = { b2 02 [2] 80 20 [2] 86 15 [2] a8 15 [2] 97 09 }

  condition:
    any of them
}