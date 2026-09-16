rule TTP_XOR_WriteProcessMemory_718d {
  strings:
    $key_718d = { 26 ff [2] 14 dd [2] 12 e8 [2] 3c e8 [2] 03 f4 }

  condition:
    any of them
}