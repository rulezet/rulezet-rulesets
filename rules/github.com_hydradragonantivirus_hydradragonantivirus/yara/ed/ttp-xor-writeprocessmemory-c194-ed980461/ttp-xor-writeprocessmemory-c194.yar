rule TTP_XOR_WriteProcessMemory_c194 {
  strings:
    $key_c194 = { 96 e6 [2] a4 c4 [2] a2 f1 [2] 8c f1 [2] b3 ed }

  condition:
    any of them
}