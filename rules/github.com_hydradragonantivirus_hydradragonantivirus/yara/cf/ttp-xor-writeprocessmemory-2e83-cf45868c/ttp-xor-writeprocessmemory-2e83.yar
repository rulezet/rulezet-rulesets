rule TTP_XOR_WriteProcessMemory_2e83 {
  strings:
    $key_2e83 = { 79 f1 [2] 4b d3 [2] 4d e6 [2] 63 e6 [2] 5c fa }

  condition:
    any of them
}