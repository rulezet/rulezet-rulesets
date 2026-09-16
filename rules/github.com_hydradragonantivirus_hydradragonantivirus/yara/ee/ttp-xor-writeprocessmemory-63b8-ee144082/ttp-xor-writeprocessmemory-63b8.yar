rule TTP_XOR_WriteProcessMemory_63b8 {
  strings:
    $key_63b8 = { 34 ca [2] 06 e8 [2] 00 dd [2] 2e dd [2] 11 c1 }

  condition:
    any of them
}