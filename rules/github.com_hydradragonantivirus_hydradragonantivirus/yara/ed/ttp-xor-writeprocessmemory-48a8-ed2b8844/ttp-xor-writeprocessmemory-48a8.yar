rule TTP_XOR_WriteProcessMemory_48a8 {
  strings:
    $key_48a8 = { 1f da [2] 2d f8 [2] 2b cd [2] 05 cd [2] 3a d1 }

  condition:
    any of them
}