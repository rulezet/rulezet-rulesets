rule TTP_XOR_WriteProcessMemory_1087 {
  strings:
    $key_1087 = { 47 f5 [2] 75 d7 [2] 73 e2 [2] 5d e2 [2] 62 fe }

  condition:
    any of them
}