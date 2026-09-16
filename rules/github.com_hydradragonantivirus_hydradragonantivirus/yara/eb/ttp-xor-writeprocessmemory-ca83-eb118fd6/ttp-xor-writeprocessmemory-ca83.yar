rule TTP_XOR_WriteProcessMemory_ca83 {
  strings:
    $key_ca83 = { 9d f1 [2] af d3 [2] a9 e6 [2] 87 e6 [2] b8 fa }

  condition:
    any of them
}