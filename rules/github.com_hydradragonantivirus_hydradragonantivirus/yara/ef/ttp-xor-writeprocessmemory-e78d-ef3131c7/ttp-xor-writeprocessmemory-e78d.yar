rule TTP_XOR_WriteProcessMemory_e78d {
  strings:
    $key_e78d = { b0 ff [2] 82 dd [2] 84 e8 [2] aa e8 [2] 95 f4 }

  condition:
    any of them
}