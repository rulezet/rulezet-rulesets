rule TTP_XOR_WriteProcessMemory_07a5 {
  strings:
    $key_07a5 = { 50 d7 [2] 62 f5 [2] 64 c0 [2] 4a c0 [2] 75 dc }

  condition:
    any of them
}