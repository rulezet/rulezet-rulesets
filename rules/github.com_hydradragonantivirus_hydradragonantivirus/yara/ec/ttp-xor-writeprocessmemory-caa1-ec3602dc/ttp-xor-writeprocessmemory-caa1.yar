rule TTP_XOR_WriteProcessMemory_caa1 {
  strings:
    $key_caa1 = { 9d d3 [2] af f1 [2] a9 c4 [2] 87 c4 [2] b8 d8 }

  condition:
    any of them
}