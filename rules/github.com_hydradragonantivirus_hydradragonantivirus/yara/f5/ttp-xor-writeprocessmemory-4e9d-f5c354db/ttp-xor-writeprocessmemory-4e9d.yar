rule TTP_XOR_WriteProcessMemory_4e9d {
  strings:
    $key_4e9d = { 19 ef [2] 2b cd [2] 2d f8 [2] 03 f8 [2] 3c e4 }

  condition:
    any of them
}