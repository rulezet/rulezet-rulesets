rule TTP_XOR_WriteProcessMemory_d552 {
  strings:
    $key_d552 = { 82 20 [2] b0 02 [2] b6 37 [2] 98 37 [2] a7 2b }

  condition:
    any of them
}