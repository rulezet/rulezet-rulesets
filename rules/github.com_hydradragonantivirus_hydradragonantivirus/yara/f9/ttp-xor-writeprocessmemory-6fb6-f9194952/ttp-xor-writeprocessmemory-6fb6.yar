rule TTP_XOR_WriteProcessMemory_6fb6 {
  strings:
    $key_6fb6 = { 38 c4 [2] 0a e6 [2] 0c d3 [2] 22 d3 [2] 1d cf }

  condition:
    any of them
}