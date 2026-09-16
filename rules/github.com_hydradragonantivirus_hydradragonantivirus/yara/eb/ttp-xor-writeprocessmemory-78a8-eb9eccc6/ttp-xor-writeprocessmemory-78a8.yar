rule TTP_XOR_WriteProcessMemory_78a8 {
  strings:
    $key_78a8 = { 2f da [2] 1d f8 [2] 1b cd [2] 35 cd [2] 0a d1 }

  condition:
    any of them
}