rule TTP_XOR_WriteProcessMemory_4c8d {
  strings:
    $key_4c8d = { 1b ff [2] 29 dd [2] 2f e8 [2] 01 e8 [2] 3e f4 }

  condition:
    any of them
}