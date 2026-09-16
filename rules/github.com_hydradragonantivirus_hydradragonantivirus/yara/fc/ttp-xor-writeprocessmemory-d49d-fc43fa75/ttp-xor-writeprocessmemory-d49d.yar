rule TTP_XOR_WriteProcessMemory_d49d {
  strings:
    $key_d49d = { 83 ef [2] b1 cd [2] b7 f8 [2] 99 f8 [2] a6 e4 }

  condition:
    any of them
}