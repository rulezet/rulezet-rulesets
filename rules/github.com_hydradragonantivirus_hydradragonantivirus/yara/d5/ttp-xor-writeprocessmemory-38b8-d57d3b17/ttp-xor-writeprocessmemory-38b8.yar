rule TTP_XOR_WriteProcessMemory_38b8 {
  strings:
    $key_38b8 = { 6f ca [2] 5d e8 [2] 5b dd [2] 75 dd [2] 4a c1 }

  condition:
    any of them
}