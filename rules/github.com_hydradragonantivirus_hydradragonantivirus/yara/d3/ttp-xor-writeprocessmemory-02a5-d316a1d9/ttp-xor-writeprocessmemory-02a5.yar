rule TTP_XOR_WriteProcessMemory_02a5 {
  strings:
    $key_02a5 = { 55 d7 [2] 67 f5 [2] 61 c0 [2] 4f c0 [2] 70 dc }

  condition:
    any of them
}