rule TTP_XOR_WriteProcessMemory_de8d {
  strings:
    $key_de8d = { 89 ff [2] bb dd [2] bd e8 [2] 93 e8 [2] ac f4 }

  condition:
    any of them
}