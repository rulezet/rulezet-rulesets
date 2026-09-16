rule TTP_XOR_WriteProcessMemory_d7a8 {
  strings:
    $key_d7a8 = { 80 da [2] b2 f8 [2] b4 cd [2] 9a cd [2] a5 d1 }

  condition:
    any of them
}