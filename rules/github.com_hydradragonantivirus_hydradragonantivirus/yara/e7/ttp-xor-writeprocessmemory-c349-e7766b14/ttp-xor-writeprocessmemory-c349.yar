rule TTP_XOR_WriteProcessMemory_c349 {
  strings:
    $key_c349 = { 94 3b [2] a6 19 [2] a0 2c [2] 8e 2c [2] b1 30 }

  condition:
    any of them
}