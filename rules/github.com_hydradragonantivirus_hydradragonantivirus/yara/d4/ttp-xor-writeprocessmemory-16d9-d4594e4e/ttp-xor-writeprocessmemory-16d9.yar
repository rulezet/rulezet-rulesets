rule TTP_XOR_WriteProcessMemory_16d9 {
  strings:
    $key_16d9 = { 41 ab [2] 73 89 [2] 75 bc [2] 5b bc [2] 64 a0 }

  condition:
    any of them
}