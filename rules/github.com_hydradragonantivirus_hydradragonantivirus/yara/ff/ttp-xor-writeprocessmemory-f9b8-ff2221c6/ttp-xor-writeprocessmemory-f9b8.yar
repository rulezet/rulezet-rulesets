rule TTP_XOR_WriteProcessMemory_f9b8 {
  strings:
    $key_f9b8 = { ae ca [2] 9c e8 [2] 9a dd [2] b4 dd [2] 8b c1 }

  condition:
    any of them
}