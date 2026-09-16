rule TTP_XOR_WriteProcessMemory_c149 {
  strings:
    $key_c149 = { 96 3b [2] a4 19 [2] a2 2c [2] 8c 2c [2] b3 30 }

  condition:
    any of them
}