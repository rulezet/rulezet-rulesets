rule TTP_XOR_WriteProcessMemory_d283 {
  strings:
    $key_d283 = { 85 f1 [2] b7 d3 [2] b1 e6 [2] 9f e6 [2] a0 fa }

  condition:
    any of them
}