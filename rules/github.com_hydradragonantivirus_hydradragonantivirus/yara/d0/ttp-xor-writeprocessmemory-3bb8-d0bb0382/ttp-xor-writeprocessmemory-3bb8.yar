rule TTP_XOR_WriteProcessMemory_3bb8 {
  strings:
    $key_3bb8 = { 6c ca [2] 5e e8 [2] 58 dd [2] 76 dd [2] 49 c1 }

  condition:
    any of them
}