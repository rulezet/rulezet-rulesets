rule TTP_XOR_WriteProcessMemory_a0b8 {
  strings:
    $key_a0b8 = { f7 ca [2] c5 e8 [2] c3 dd [2] ed dd [2] d2 c1 }

  condition:
    any of them
}