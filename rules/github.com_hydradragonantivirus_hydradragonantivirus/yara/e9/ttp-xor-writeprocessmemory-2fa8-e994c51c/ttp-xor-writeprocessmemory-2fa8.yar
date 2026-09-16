rule TTP_XOR_WriteProcessMemory_2fa8 {
  strings:
    $key_2fa8 = { 78 da [2] 4a f8 [2] 4c cd [2] 62 cd [2] 5d d1 }

  condition:
    any of them
}