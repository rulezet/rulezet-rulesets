rule TTP_XOR_WriteProcessMemory_50a8 {
  strings:
    $key_50a8 = { 07 da [2] 35 f8 [2] 33 cd [2] 1d cd [2] 22 d1 }

  condition:
    any of them
}