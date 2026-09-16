rule TTP_XOR_WriteProcessMemory_5d8d {
  strings:
    $key_5d8d = { 0a ff [2] 38 dd [2] 3e e8 [2] 10 e8 [2] 2f f4 }

  condition:
    any of them
}