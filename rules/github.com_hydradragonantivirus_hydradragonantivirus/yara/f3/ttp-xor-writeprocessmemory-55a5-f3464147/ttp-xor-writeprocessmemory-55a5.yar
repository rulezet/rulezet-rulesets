rule TTP_XOR_WriteProcessMemory_55a5 {
  strings:
    $key_55a5 = { 02 d7 [2] 30 f5 [2] 36 c0 [2] 18 c0 [2] 27 dc }

  condition:
    any of them
}