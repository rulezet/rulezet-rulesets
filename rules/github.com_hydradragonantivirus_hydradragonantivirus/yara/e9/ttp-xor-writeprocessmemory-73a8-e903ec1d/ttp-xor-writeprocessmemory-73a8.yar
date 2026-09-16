rule TTP_XOR_WriteProcessMemory_73a8 {
  strings:
    $key_73a8 = { 24 da [2] 16 f8 [2] 10 cd [2] 3e cd [2] 01 d1 }

  condition:
    any of them
}