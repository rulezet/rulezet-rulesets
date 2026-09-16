rule TTP_XOR_WriteProcessMemory_c106 {
  strings:
    $key_c106 = { 96 74 [2] a4 56 [2] a2 63 [2] 8c 63 [2] b3 7f }

  condition:
    any of them
}