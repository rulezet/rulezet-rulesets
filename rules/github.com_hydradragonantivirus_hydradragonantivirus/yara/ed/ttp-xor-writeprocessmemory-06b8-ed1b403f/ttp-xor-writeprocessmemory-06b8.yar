rule TTP_XOR_WriteProcessMemory_06b8 {
  strings:
    $key_06b8 = { 51 ca [2] 63 e8 [2] 65 dd [2] 4b dd [2] 74 c1 }

  condition:
    any of them
}