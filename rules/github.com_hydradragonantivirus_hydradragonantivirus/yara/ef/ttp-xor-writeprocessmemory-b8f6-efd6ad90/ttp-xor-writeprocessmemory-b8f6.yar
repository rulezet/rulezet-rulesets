rule TTP_XOR_WriteProcessMemory_b8f6 {
  strings:
    $key_b8f6 = { ef 84 [2] dd a6 [2] db 93 [2] f5 93 [2] ca 8f }

  condition:
    any of them
}