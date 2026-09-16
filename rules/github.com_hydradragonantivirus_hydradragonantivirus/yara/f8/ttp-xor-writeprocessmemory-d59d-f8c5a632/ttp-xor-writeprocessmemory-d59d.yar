rule TTP_XOR_WriteProcessMemory_d59d {
  strings:
    $key_d59d = { 82 ef [2] b0 cd [2] b6 f8 [2] 98 f8 [2] a7 e4 }

  condition:
    any of them
}