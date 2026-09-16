rule TTP_XOR_WriteProcessMemory_b6b8 {
  strings:
    $key_b6b8 = { e1 ca [2] d3 e8 [2] d5 dd [2] fb dd [2] c4 c1 }

  condition:
    any of them
}