rule TTP_XOR_WriteProcessMemory_41a8 {
  strings:
    $key_41a8 = { 16 da [2] 24 f8 [2] 22 cd [2] 0c cd [2] 33 d1 }

  condition:
    any of them
}