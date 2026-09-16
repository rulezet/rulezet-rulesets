rule TTP_XOR_WriteProcessMemory_04b8 {
  strings:
    $key_04b8 = { 53 ca [2] 61 e8 [2] 67 dd [2] 49 dd [2] 76 c1 }

  condition:
    any of them
}