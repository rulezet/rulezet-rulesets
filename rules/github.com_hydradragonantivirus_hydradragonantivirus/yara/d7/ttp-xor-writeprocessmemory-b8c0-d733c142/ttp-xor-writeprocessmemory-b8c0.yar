rule TTP_XOR_WriteProcessMemory_b8c0 {
  strings:
    $key_b8c0 = { ef b2 [2] dd 90 [2] db a5 [2] f5 a5 [2] ca b9 }

  condition:
    any of them
}