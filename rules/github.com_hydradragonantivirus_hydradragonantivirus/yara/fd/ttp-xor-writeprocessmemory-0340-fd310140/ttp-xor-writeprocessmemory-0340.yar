rule TTP_XOR_WriteProcessMemory_0340 {
  strings:
    $key_0340 = { 54 32 [2] 66 10 [2] 60 25 [2] 4e 25 [2] 71 39 }

  condition:
    any of them
}