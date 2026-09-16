rule TTP_XOR_WriteProcessMemory_16c3 {
  strings:
    $key_16c3 = { 41 b1 [2] 73 93 [2] 75 a6 [2] 5b a6 [2] 64 ba }

  condition:
    any of them
}