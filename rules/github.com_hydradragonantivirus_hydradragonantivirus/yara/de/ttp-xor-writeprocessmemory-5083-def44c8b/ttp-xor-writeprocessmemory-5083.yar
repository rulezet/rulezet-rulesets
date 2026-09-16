rule TTP_XOR_WriteProcessMemory_5083 {
  strings:
    $key_5083 = { 07 f1 [2] 35 d3 [2] 33 e6 [2] 1d e6 [2] 22 fa }

  condition:
    any of them
}