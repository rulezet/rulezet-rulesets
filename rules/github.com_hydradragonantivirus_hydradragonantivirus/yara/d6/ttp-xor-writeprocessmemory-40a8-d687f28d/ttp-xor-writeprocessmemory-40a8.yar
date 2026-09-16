rule TTP_XOR_WriteProcessMemory_40a8 {
  strings:
    $key_40a8 = { 17 da [2] 25 f8 [2] 23 cd [2] 0d cd [2] 32 d1 }

  condition:
    any of them
}