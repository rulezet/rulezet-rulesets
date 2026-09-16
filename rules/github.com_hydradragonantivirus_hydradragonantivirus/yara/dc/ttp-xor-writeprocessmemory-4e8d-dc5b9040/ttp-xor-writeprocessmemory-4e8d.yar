rule TTP_XOR_WriteProcessMemory_4e8d {
  strings:
    $key_4e8d = { 19 ff [2] 2b dd [2] 2d e8 [2] 03 e8 [2] 3c f4 }

  condition:
    any of them
}