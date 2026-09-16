rule TTP_XOR_WriteProcessMemory_7883 {
  strings:
    $key_7883 = { 2f f1 [2] 1d d3 [2] 1b e6 [2] 35 e6 [2] 0a fa }

  condition:
    any of them
}