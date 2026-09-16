rule TTP_XOR_WriteProcessMemory_32b8 {
  strings:
    $key_32b8 = { 65 ca [2] 57 e8 [2] 51 dd [2] 7f dd [2] 40 c1 }

  condition:
    any of them
}