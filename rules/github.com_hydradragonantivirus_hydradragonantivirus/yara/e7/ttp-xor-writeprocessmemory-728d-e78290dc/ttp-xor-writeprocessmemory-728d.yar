rule TTP_XOR_WriteProcessMemory_728d {
  strings:
    $key_728d = { 25 ff [2] 17 dd [2] 11 e8 [2] 3f e8 [2] 00 f4 }

  condition:
    any of them
}