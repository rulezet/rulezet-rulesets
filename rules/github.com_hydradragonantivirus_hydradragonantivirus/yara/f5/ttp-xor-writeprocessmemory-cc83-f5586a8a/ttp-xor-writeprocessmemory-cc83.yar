rule TTP_XOR_WriteProcessMemory_cc83 {
  strings:
    $key_cc83 = { 9b f1 [2] a9 d3 [2] af e6 [2] 81 e6 [2] be fa }

  condition:
    any of them
}