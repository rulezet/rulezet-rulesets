rule TTP_XOR_WriteProcessMemory_3691 {
  strings:
    $key_3691 = { 61 e3 [2] 53 c1 [2] 55 f4 [2] 7b f4 [2] 44 e8 }

  condition:
    any of them
}