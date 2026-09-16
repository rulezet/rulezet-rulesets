rule TTP_XOR_WriteProcessMemory_01a8 {
  strings:
    $key_01a8 = { 56 da [2] 64 f8 [2] 62 cd [2] 4c cd [2] 73 d1 }

  condition:
    any of them
}