rule TTP_XOR_WriteProcessMemory_08b8 {
  strings:
    $key_08b8 = { 5f ca [2] 6d e8 [2] 6b dd [2] 45 dd [2] 7a c1 }

  condition:
    any of them
}