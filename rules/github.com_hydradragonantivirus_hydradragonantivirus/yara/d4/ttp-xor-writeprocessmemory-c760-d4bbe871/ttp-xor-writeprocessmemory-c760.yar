rule TTP_XOR_WriteProcessMemory_c760 {
  strings:
    $key_c760 = { 90 12 [2] a2 30 [2] a4 05 [2] 8a 05 [2] b5 19 }

  condition:
    any of them
}