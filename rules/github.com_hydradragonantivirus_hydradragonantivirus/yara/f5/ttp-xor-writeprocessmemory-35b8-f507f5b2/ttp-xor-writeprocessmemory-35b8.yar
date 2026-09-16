rule TTP_XOR_WriteProcessMemory_35b8 {
  strings:
    $key_35b8 = { 62 ca [2] 50 e8 [2] 56 dd [2] 78 dd [2] 47 c1 }

  condition:
    any of them
}