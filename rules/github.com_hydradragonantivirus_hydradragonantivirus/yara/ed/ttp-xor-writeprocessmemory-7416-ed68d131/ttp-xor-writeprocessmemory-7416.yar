rule TTP_XOR_WriteProcessMemory_7416 {
  strings:
    $key_7416 = { 23 64 [2] 11 46 [2] 17 73 [2] 39 73 [2] 06 6f }

  condition:
    any of them
}