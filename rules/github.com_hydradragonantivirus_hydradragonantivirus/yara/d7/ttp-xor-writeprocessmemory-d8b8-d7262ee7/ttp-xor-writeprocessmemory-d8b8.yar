rule TTP_XOR_WriteProcessMemory_d8b8 {
  strings:
    $key_d8b8 = { 8f ca [2] bd e8 [2] bb dd [2] 95 dd [2] aa c1 }

  condition:
    any of them
}