rule TTP_XOR_WriteProcessMemory_1091 {
  strings:
    $key_1091 = { 47 e3 [2] 75 c1 [2] 73 f4 [2] 5d f4 [2] 62 e8 }

  condition:
    any of them
}