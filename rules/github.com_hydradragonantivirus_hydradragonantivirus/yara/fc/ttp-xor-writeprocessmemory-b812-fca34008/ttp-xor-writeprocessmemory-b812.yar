rule TTP_XOR_WriteProcessMemory_b812 {
  strings:
    $key_b812 = { ef 60 [2] dd 42 [2] db 77 [2] f5 77 [2] ca 6b }

  condition:
    any of them
}