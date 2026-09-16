rule TTP_XOR_WriteProcessMemory_18b8 {
  strings:
    $key_18b8 = { 4f ca [2] 7d e8 [2] 7b dd [2] 55 dd [2] 6a c1 }

  condition:
    any of them
}