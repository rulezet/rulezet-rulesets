rule TTP_XOR_WriteProcessMemory_34b8 {
  strings:
    $key_34b8 = { 63 ca [2] 51 e8 [2] 57 dd [2] 79 dd [2] 46 c1 }

  condition:
    any of them
}