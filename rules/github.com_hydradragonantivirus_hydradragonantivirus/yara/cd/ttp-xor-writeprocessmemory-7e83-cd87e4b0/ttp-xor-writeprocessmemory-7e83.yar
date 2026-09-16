rule TTP_XOR_WriteProcessMemory_7e83 {
  strings:
    $key_7e83 = { 29 f1 [2] 1b d3 [2] 1d e6 [2] 33 e6 [2] 0c fa }

  condition:
    any of them
}