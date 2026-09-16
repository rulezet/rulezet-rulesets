rule TTP_XOR_WriteProcessMemory_cbb4 {
  strings:
    $key_cbb4 = { 9c c6 [2] ae e4 [2] a8 d1 [2] 86 d1 [2] b9 cd }

  condition:
    any of them
}