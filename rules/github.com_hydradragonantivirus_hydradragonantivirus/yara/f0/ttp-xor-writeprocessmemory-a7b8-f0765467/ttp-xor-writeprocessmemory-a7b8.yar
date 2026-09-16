rule TTP_XOR_WriteProcessMemory_a7b8 {
  strings:
    $key_a7b8 = { f0 ca [2] c2 e8 [2] c4 dd [2] ea dd [2] d5 c1 }

  condition:
    any of them
}