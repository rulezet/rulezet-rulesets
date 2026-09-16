rule TTP_XOR_WriteProcessMemory_d19d {
  strings:
    $key_d19d = { 86 ef [2] b4 cd [2] b2 f8 [2] 9c f8 [2] a3 e4 }

  condition:
    any of them
}