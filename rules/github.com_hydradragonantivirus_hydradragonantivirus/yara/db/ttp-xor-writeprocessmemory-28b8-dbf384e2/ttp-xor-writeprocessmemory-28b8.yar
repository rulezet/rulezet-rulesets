rule TTP_XOR_WriteProcessMemory_28b8 {
  strings:
    $key_28b8 = { 7f ca [2] 4d e8 [2] 4b dd [2] 65 dd [2] 5a c1 }

  condition:
    any of them
}