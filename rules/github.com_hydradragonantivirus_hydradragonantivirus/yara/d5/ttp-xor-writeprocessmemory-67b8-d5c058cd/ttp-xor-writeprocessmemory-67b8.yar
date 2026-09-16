rule TTP_XOR_WriteProcessMemory_67b8 {
  strings:
    $key_67b8 = { 30 ca [2] 02 e8 [2] 04 dd [2] 2a dd [2] 15 c1 }

  condition:
    any of them
}