rule TTP_XOR_WriteProcessMemory_c483 {
  strings:
    $key_c483 = { 93 f1 [2] a1 d3 [2] a7 e6 [2] 89 e6 [2] b6 fa }

  condition:
    any of them
}