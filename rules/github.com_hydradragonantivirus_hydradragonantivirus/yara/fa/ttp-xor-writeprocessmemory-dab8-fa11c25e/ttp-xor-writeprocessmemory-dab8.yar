rule TTP_XOR_WriteProcessMemory_dab8 {
  strings:
    $key_dab8 = { 8d ca [2] bf e8 [2] b9 dd [2] 97 dd [2] a8 c1 }

  condition:
    any of them
}