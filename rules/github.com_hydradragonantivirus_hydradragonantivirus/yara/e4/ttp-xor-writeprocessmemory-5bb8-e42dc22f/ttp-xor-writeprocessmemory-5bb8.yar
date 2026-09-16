rule TTP_XOR_WriteProcessMemory_5bb8 {
  strings:
    $key_5bb8 = { 0c ca [2] 3e e8 [2] 38 dd [2] 16 dd [2] 29 c1 }

  condition:
    any of them
}