rule TTP_XOR_WriteProcessMemory_0391 {
  strings:
    $key_0391 = { 54 e3 [2] 66 c1 [2] 60 f4 [2] 4e f4 [2] 71 e8 }

  condition:
    any of them
}