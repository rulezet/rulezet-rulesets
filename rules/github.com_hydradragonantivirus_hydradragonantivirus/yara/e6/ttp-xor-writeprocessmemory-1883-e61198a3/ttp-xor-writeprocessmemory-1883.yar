rule TTP_XOR_WriteProcessMemory_1883 {
  strings:
    $key_1883 = { 4f f1 [2] 7d d3 [2] 7b e6 [2] 55 e6 [2] 6a fa }

  condition:
    any of them
}