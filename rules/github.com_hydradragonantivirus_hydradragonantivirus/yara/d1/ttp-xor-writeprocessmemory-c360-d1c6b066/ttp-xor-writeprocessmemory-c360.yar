rule TTP_XOR_WriteProcessMemory_c360 {
  strings:
    $key_c360 = { 94 12 [2] a6 30 [2] a0 05 [2] 8e 05 [2] b1 19 }

  condition:
    any of them
}