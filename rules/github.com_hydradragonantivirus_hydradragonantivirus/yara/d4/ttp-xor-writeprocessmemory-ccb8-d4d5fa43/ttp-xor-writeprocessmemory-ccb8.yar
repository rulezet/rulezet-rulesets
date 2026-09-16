rule TTP_XOR_WriteProcessMemory_ccb8 {
  strings:
    $key_ccb8 = { 9b ca [2] a9 e8 [2] af dd [2] 81 dd [2] be c1 }

  condition:
    any of them
}