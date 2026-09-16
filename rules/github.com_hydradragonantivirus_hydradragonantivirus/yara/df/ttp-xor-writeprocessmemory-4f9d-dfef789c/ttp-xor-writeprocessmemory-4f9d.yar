rule TTP_XOR_WriteProcessMemory_4f9d {
  strings:
    $key_4f9d = { 18 ef [2] 2a cd [2] 2c f8 [2] 02 f8 [2] 3d e4 }

  condition:
    any of them
}