rule TTP_XOR_WriteProcessMemory_1fa8 {
  strings:
    $key_1fa8 = { 48 da [2] 7a f8 [2] 7c cd [2] 52 cd [2] 6d d1 }

  condition:
    any of them
}