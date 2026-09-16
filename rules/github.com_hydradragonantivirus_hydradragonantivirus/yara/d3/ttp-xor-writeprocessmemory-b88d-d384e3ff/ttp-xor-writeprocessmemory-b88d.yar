rule TTP_XOR_WriteProcessMemory_b88d {
  strings:
    $key_b88d = { ef ff [2] dd dd [2] db e8 [2] f5 e8 [2] ca f4 }

  condition:
    any of them
}