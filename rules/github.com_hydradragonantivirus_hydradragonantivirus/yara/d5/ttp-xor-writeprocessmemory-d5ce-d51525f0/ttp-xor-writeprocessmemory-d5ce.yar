rule TTP_XOR_WriteProcessMemory_d5ce {
  strings:
    $key_d5ce = { 82 bc [2] b0 9e [2] b6 ab [2] 98 ab [2] a7 b7 }

  condition:
    any of them
}