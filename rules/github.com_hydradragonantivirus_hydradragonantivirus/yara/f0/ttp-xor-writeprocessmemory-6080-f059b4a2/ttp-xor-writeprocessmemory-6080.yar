rule TTP_XOR_WriteProcessMemory_6080 {
  strings:
    $key_6080 = { 37 f2 [2] 05 d0 [2] 03 e5 [2] 2d e5 [2] 12 f9 }

  condition:
    any of them
}