rule TTP_XOR_WriteProcessMemory_d6ce {
  strings:
    $key_d6ce = { 81 bc [2] b3 9e [2] b5 ab [2] 9b ab [2] a4 b7 }

  condition:
    any of them
}