rule TTP_XOR_WriteProcessMemory_7691 {
  strings:
    $key_7691 = { 21 e3 [2] 13 c1 [2] 15 f4 [2] 3b f4 [2] 04 e8 }

  condition:
    any of them
}