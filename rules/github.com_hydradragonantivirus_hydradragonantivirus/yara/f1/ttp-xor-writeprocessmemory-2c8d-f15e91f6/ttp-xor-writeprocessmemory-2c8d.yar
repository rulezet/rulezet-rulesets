rule TTP_XOR_WriteProcessMemory_2c8d {
  strings:
    $key_2c8d = { 7b ff [2] 49 dd [2] 4f e8 [2] 61 e8 [2] 5e f4 }

  condition:
    any of them
}