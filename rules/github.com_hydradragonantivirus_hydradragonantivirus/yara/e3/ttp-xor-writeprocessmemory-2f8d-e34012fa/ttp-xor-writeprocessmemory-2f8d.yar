rule TTP_XOR_WriteProcessMemory_2f8d {
  strings:
    $key_2f8d = { 78 ff [2] 4a dd [2] 4c e8 [2] 62 e8 [2] 5d f4 }

  condition:
    any of them
}