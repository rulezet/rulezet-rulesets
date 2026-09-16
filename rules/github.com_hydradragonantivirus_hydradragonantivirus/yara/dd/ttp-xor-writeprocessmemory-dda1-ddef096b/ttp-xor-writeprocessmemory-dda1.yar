rule TTP_XOR_WriteProcessMemory_dda1 {
  strings:
    $key_dda1 = { 8a d3 [2] b8 f1 [2] be c4 [2] 90 c4 [2] af d8 }

  condition:
    any of them
}