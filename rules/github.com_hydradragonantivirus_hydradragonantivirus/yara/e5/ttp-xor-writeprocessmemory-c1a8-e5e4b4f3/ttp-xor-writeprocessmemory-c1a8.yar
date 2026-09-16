rule TTP_XOR_WriteProcessMemory_c1a8 {
  strings:
    $key_c1a8 = { 96 da [2] a4 f8 [2] a2 cd [2] 8c cd [2] b3 d1 }

  condition:
    any of them
}