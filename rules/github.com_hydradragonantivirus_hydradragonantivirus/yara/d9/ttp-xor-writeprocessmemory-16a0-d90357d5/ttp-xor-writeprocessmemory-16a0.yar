rule TTP_XOR_WriteProcessMemory_16a0 {
  strings:
    $key_16a0 = { 41 d2 [2] 73 f0 [2] 75 c5 [2] 5b c5 [2] 64 d9 }

  condition:
    any of them
}