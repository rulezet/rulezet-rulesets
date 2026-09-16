rule TTP_XOR_WriteProcessMemory_e79d {
  strings:
    $key_e79d = { b0 ef [2] 82 cd [2] 84 f8 [2] aa f8 [2] 95 e4 }

  condition:
    any of them
}