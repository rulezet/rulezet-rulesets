rule TTP_XOR_WriteProcessMemory_43b8 {
  strings:
    $key_43b8 = { 14 ca [2] 26 e8 [2] 20 dd [2] 0e dd [2] 31 c1 }

  condition:
    any of them
}