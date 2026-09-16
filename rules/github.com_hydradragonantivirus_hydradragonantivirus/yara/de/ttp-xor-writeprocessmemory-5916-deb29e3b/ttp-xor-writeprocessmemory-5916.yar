rule TTP_XOR_WriteProcessMemory_5916 {
  strings:
    $key_5916 = { 0e 64 [2] 3c 46 [2] 3a 73 [2] 14 73 [2] 2b 6f }

  condition:
    any of them
}