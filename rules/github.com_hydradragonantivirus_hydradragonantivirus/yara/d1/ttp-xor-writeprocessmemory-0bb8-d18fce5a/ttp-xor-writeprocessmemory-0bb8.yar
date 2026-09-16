rule TTP_XOR_WriteProcessMemory_0bb8 {
  strings:
    $key_0bb8 = { 5c ca [2] 6e e8 [2] 68 dd [2] 46 dd [2] 79 c1 }

  condition:
    any of them
}