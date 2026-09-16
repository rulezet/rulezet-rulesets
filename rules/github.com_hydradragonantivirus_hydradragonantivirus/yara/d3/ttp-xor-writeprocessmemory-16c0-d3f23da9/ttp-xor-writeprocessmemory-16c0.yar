rule TTP_XOR_WriteProcessMemory_16c0 {
  strings:
    $key_16c0 = { 41 b2 [2] 73 90 [2] 75 a5 [2] 5b a5 [2] 64 b9 }

  condition:
    any of them
}