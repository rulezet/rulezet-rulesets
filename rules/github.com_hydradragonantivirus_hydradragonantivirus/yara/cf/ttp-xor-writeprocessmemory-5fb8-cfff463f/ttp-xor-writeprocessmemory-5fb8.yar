rule TTP_XOR_WriteProcessMemory_5fb8 {
  strings:
    $key_5fb8 = { 08 ca [2] 3a e8 [2] 3c dd [2] 12 dd [2] 2d c1 }

  condition:
    any of them
}