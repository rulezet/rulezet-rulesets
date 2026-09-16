rule TTP_XOR_WriteProcessMemory_bef5 {
  strings:
    $key_bef5 = { e9 87 [2] db a5 [2] dd 90 [2] f3 90 [2] cc 8c }

  condition:
    any of them
}