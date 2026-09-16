rule TTP_XOR_WriteProcessMemory_b8c1 {
  strings:
    $key_b8c1 = { ef b3 [2] dd 91 [2] db a4 [2] f5 a4 [2] ca b8 }

  condition:
    any of them
}