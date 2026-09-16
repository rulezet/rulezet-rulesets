rule TTP_XOR_WriteProcessMemory_c49d {
  strings:
    $key_c49d = { 93 ef [2] a1 cd [2] a7 f8 [2] 89 f8 [2] b6 e4 }

  condition:
    any of them
}