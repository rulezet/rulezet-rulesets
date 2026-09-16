rule TTP_XOR_WriteProcessMemory_c452 {
  strings:
    $key_c452 = { 93 20 [2] a1 02 [2] a7 37 [2] 89 37 [2] b6 2b }

  condition:
    any of them
}