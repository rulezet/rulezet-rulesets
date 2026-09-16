rule TTP_XOR_WriteProcessMemory_d8f3 {
  strings:
    $key_d8f3 = { 8f 81 [2] bd a3 [2] bb 96 [2] 95 96 [2] aa 8a }

  condition:
    any of them
}