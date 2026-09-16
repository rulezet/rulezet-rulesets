rule TTP_XOR_WriteProcessMemory_cbb8 {
  strings:
    $key_cbb8 = { 9c ca [2] ae e8 [2] a8 dd [2] 86 dd [2] b9 c1 }

  condition:
    any of them
}