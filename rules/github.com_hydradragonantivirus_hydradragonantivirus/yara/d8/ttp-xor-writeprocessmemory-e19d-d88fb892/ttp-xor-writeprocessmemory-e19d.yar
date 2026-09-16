rule TTP_XOR_WriteProcessMemory_e19d {
  strings:
    $key_e19d = { b6 ef [2] 84 cd [2] 82 f8 [2] ac f8 [2] 93 e4 }

  condition:
    any of them
}