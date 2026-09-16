rule TTP_XOR_WriteProcessMemory_b830 {
  strings:
    $key_b830 = { ef 42 [2] dd 60 [2] db 55 [2] f5 55 [2] ca 49 }

  condition:
    any of them
}