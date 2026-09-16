rule TTP_XOR_WriteProcessMemory_5fa8 {
  strings:
    $key_5fa8 = { 08 da [2] 3a f8 [2] 3c cd [2] 12 cd [2] 2d d1 }

  condition:
    any of them
}