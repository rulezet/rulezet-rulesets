rule TTP_XOR_WriteProcessMemory_01a5 {
  strings:
    $key_01a5 = { 56 d7 [2] 64 f5 [2] 62 c0 [2] 4c c0 [2] 73 dc }

  condition:
    any of them
}