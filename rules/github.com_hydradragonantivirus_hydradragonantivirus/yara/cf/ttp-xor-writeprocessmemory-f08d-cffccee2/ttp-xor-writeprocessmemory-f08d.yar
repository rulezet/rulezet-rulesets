rule TTP_XOR_WriteProcessMemory_f08d {
  strings:
    $key_f08d = { a7 ff [2] 95 dd [2] 93 e8 [2] bd e8 [2] 82 f4 }

  condition:
    any of them
}