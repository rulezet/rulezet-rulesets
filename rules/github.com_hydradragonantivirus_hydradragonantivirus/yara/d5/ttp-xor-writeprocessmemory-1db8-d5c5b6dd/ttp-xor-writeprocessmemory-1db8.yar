rule TTP_XOR_WriteProcessMemory_1db8 {
  strings:
    $key_1db8 = { 4a ca [2] 78 e8 [2] 7e dd [2] 50 dd [2] 6f c1 }

  condition:
    any of them
}