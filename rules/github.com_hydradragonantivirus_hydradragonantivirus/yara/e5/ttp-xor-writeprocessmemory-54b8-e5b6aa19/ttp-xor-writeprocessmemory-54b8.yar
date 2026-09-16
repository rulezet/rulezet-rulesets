rule TTP_XOR_WriteProcessMemory_54b8 {
  strings:
    $key_54b8 = { 03 ca [2] 31 e8 [2] 37 dd [2] 19 dd [2] 26 c1 }

  condition:
    any of them
}