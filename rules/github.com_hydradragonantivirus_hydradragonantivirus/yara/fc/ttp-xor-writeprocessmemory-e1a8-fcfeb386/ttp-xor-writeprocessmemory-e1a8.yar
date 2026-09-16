rule TTP_XOR_WriteProcessMemory_e1a8 {
  strings:
    $key_e1a8 = { b6 da [2] 84 f8 [2] 82 cd [2] ac cd [2] 93 d1 }

  condition:
    any of them
}