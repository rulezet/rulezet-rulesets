rule TTP_XOR_WriteProcessMemory_1c8d {
  strings:
    $key_1c8d = { 4b ff [2] 79 dd [2] 7f e8 [2] 51 e8 [2] 6e f4 }

  condition:
    any of them
}