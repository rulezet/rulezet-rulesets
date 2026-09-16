rule TTP_XOR_WriteProcessMemory_b8c6 {
  strings:
    $key_b8c6 = { ef b4 [2] dd 96 [2] db a3 [2] f5 a3 [2] ca bf }

  condition:
    any of them
}