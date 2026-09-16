rule TTP_XOR_WriteProcessMemory_55b8 {
  strings:
    $key_55b8 = { 02 ca [2] 30 e8 [2] 36 dd [2] 18 dd [2] 27 c1 }

  condition:
    any of them
}