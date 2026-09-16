rule TTP_XOR_WriteProcessMemory_5683 {
  strings:
    $key_5683 = { 01 f1 [2] 33 d3 [2] 35 e6 [2] 1b e6 [2] 24 fa }

  condition:
    any of them
}