rule TTP_XOR_WriteProcessMemory_44a5 {
  strings:
    $key_44a5 = { 13 d7 [2] 21 f5 [2] 27 c0 [2] 09 c0 [2] 36 dc }

  condition:
    any of them
}