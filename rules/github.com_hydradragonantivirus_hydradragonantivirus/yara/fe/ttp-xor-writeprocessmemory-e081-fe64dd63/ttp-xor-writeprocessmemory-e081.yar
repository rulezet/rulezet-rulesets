rule TTP_XOR_WriteProcessMemory_e081 {
  strings:
    $key_e081 = { b7 f3 [2] 85 d1 [2] 83 e4 [2] ad e4 [2] 92 f8 }

  condition:
    any of them
}