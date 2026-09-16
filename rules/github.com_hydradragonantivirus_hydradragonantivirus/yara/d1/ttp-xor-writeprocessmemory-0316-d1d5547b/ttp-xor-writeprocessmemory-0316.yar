rule TTP_XOR_WriteProcessMemory_0316 {
  strings:
    $key_0316 = { 54 64 [2] 66 46 [2] 60 73 [2] 4e 73 [2] 71 6f }

  condition:
    any of them
}