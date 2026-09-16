rule TTP_XOR_WriteProcessMemory_4f8a {
  strings:
    $key_4f8a = { 18 f8 [2] 2a da [2] 2c ef [2] 02 ef [2] 3d f3 }

  condition:
    any of them
}