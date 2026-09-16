rule TTP_XOR_WriteProcessMemory_5691 {
  strings:
    $key_5691 = { 01 e3 [2] 33 c1 [2] 35 f4 [2] 1b f4 [2] 24 e8 }

  condition:
    any of them
}