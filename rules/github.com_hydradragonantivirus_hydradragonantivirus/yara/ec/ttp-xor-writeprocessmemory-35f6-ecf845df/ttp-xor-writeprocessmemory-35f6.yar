rule TTP_XOR_WriteProcessMemory_35f6 {
  strings:
    $key_35f6 = { 62 84 [2] 50 a6 [2] 56 93 [2] 78 93 [2] 47 8f }

  condition:
    any of them
}