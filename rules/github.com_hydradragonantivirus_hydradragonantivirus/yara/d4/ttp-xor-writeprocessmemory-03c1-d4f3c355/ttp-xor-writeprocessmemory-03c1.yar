rule TTP_XOR_WriteProcessMemory_03c1 {
  strings:
    $key_03c1 = { 54 b3 [2] 66 91 [2] 60 a4 [2] 4e a4 [2] 71 b8 }

  condition:
    any of them
}