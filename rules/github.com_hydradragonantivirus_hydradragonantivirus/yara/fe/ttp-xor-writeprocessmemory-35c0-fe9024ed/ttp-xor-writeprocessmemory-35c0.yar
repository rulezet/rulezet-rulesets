rule TTP_XOR_WriteProcessMemory_35c0 {
  strings:
    $key_35c0 = { 62 b2 [2] 50 90 [2] 56 a5 [2] 78 a5 [2] 47 b9 }

  condition:
    any of them
}