rule TTP_XOR_WriteProcessMemory_f5b8 {
  strings:
    $key_f5b8 = { a2 ca [2] 90 e8 [2] 96 dd [2] b8 dd [2] 87 c1 }

  condition:
    any of them
}