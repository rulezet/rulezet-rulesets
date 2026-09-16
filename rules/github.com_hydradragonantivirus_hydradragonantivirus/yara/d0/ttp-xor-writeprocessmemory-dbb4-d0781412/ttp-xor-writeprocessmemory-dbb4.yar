rule TTP_XOR_WriteProcessMemory_dbb4 {
  strings:
    $key_dbb4 = { 8c c6 [2] be e4 [2] b8 d1 [2] 96 d1 [2] a9 cd }

  condition:
    any of them
}