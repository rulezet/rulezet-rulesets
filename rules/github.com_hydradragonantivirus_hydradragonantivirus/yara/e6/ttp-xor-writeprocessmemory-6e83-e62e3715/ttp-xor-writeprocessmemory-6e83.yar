rule TTP_XOR_WriteProcessMemory_6e83 {
  strings:
    $key_6e83 = { 39 f1 [2] 0b d3 [2] 0d e6 [2] 23 e6 [2] 1c fa }

  condition:
    any of them
}