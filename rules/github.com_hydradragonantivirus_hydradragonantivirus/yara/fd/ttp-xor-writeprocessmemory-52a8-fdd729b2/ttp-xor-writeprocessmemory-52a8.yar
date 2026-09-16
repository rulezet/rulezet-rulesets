rule TTP_XOR_WriteProcessMemory_52a8 {
  strings:
    $key_52a8 = { 05 da [2] 37 f8 [2] 31 cd [2] 1f cd [2] 20 d1 }

  condition:
    any of them
}