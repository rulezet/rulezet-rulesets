rule TTP_XOR_WriteProcessMemory_168d {
  strings:
    $key_168d = { 41 ff [2] 73 dd [2] 75 e8 [2] 5b e8 [2] 64 f4 }

  condition:
    any of them
}