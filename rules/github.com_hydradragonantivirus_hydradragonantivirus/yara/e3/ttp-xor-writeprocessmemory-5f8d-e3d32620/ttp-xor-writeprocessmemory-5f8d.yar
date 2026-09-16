rule TTP_XOR_WriteProcessMemory_5f8d {
  strings:
    $key_5f8d = { 08 ff [2] 3a dd [2] 3c e8 [2] 12 e8 [2] 2d f4 }

  condition:
    any of them
}