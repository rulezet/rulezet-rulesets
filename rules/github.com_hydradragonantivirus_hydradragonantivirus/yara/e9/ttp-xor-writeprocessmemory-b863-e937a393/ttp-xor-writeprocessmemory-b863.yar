rule TTP_XOR_WriteProcessMemory_b863 {
  strings:
    $key_b863 = { ef 11 [2] dd 33 [2] db 06 [2] f5 06 [2] ca 1a }

  condition:
    any of them
}