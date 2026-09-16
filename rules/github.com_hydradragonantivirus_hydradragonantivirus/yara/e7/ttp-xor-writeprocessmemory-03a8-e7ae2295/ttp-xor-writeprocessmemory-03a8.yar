rule TTP_XOR_WriteProcessMemory_03a8 {
  strings:
    $key_03a8 = { 54 da [2] 66 f8 [2] 60 cd [2] 4e cd [2] 71 d1 }

  condition:
    any of them
}