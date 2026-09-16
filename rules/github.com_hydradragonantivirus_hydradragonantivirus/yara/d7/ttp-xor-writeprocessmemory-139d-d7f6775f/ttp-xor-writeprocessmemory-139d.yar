rule TTP_XOR_WriteProcessMemory_139d {
  strings:
    $key_139d = { 44 ef [2] 76 cd [2] 70 f8 [2] 5e f8 [2] 61 e4 }

  condition:
    any of them
}