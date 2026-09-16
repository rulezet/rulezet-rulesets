rule TTP_XOR_WriteProcessMemory_56b8 {
  strings:
    $key_56b8 = { 01 ca [2] 33 e8 [2] 35 dd [2] 1b dd [2] 24 c1 }

  condition:
    any of them
}