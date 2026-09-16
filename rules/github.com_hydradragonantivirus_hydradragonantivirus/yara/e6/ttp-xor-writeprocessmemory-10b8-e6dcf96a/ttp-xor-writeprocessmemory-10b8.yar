rule TTP_XOR_WriteProcessMemory_10b8 {
  strings:
    $key_10b8 = { 47 ca [2] 75 e8 [2] 73 dd [2] 5d dd [2] 62 c1 }

  condition:
    any of them
}