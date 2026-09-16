rule TTP_XOR_WriteProcessMemory_35c3 {
  strings:
    $key_35c3 = { 62 b1 [2] 50 93 [2] 56 a6 [2] 78 a6 [2] 47 ba }

  condition:
    any of them
}