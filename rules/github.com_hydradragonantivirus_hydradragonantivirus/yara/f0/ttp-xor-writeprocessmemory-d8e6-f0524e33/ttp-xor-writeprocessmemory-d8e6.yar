rule TTP_XOR_WriteProcessMemory_d8e6 {
  strings:
    $key_d8e6 = { 8f 94 [2] bd b6 [2] bb 83 [2] 95 83 [2] aa 9f }

  condition:
    any of them
}