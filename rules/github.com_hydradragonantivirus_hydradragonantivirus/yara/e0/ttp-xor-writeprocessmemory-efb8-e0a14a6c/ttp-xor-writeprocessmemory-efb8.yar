rule TTP_XOR_WriteProcessMemory_efb8 {
  strings:
    $key_efb8 = { b8 ca [2] 8a e8 [2] 8c dd [2] a2 dd [2] 9d c1 }

  condition:
    any of them
}