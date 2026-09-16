rule TTP_XOR_WriteProcessMemory_5b8d {
  strings:
    $key_5b8d = { 0c ff [2] 3e dd [2] 38 e8 [2] 16 e8 [2] 29 f4 }

  condition:
    any of them
}