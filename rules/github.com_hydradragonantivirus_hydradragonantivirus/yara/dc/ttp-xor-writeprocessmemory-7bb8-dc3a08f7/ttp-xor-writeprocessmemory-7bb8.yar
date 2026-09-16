rule TTP_XOR_WriteProcessMemory_7bb8 {
  strings:
    $key_7bb8 = { 2c ca [2] 1e e8 [2] 18 dd [2] 36 dd [2] 09 c1 }

  condition:
    any of them
}