rule TTP_XOR_WriteProcessMemory_62a8 {
  strings:
    $key_62a8 = { 35 da [2] 07 f8 [2] 01 cd [2] 2f cd [2] 10 d1 }

  condition:
    any of them
}