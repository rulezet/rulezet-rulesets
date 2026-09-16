rule TTP_XOR_WriteProcessMemory_778d {
  strings:
    $key_778d = { 20 ff [2] 12 dd [2] 14 e8 [2] 3a e8 [2] 05 f4 }

  condition:
    any of them
}