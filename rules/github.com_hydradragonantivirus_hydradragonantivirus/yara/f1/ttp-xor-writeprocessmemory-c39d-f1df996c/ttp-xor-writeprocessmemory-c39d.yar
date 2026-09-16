rule TTP_XOR_WriteProcessMemory_c39d {
  strings:
    $key_c39d = { 94 ef [2] a6 cd [2] a0 f8 [2] 8e f8 [2] b1 e4 }

  condition:
    any of them
}