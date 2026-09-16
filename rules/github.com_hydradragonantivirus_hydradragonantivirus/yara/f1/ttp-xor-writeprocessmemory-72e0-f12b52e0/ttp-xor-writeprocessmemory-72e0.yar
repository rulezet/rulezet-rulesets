rule TTP_XOR_WriteProcessMemory_72e0 {
  strings:
    $key_72e0 = { 25 92 [2] 17 b0 [2] 11 85 [2] 3f 85 [2] 00 99 }

  condition:
    any of them
}