rule TTP_XOR_WriteProcessMemory_13b8 {
  strings:
    $key_13b8 = { 44 ca [2] 76 e8 [2] 70 dd [2] 5e dd [2] 61 c1 }

  condition:
    any of them
}