rule TTP_XOR_WriteProcessMemory_d1a8 {
  strings:
    $key_d1a8 = { 86 da [2] b4 f8 [2] b2 cd [2] 9c cd [2] a3 d1 }

  condition:
    any of them
}