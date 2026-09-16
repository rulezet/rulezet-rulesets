rule TTP_XOR_WriteProcessMemory_6190 {
  strings:
    $key_6190 = { 36 e2 [2] 04 c0 [2] 02 f5 [2] 2c f5 [2] 13 e9 }

  condition:
    any of them
}