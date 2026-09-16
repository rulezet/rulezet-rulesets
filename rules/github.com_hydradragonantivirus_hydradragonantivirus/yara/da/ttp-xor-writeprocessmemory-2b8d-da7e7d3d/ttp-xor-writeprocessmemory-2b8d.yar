rule TTP_XOR_WriteProcessMemory_2b8d {
  strings:
    $key_2b8d = { 7c ff [2] 4e dd [2] 48 e8 [2] 66 e8 [2] 59 f4 }

  condition:
    any of them
}