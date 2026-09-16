rule TTP_XOR_WriteProcessMemory_73a5 {
  strings:
    $key_73a5 = { 24 d7 [2] 16 f5 [2] 10 c0 [2] 3e c0 [2] 01 dc }

  condition:
    any of them
}