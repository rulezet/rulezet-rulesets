rule TTP_XOR_WriteProcessMemory_d483 {
  strings:
    $key_d483 = { 83 f1 [2] b1 d3 [2] b7 e6 [2] 99 e6 [2] a6 fa }

  condition:
    any of them
}