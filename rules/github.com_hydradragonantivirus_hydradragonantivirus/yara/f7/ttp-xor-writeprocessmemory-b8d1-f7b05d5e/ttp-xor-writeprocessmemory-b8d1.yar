rule TTP_XOR_WriteProcessMemory_b8d1 {
  strings:
    $key_b8d1 = { ef a3 [2] dd 81 [2] db b4 [2] f5 b4 [2] ca a8 }

  condition:
    any of them
}