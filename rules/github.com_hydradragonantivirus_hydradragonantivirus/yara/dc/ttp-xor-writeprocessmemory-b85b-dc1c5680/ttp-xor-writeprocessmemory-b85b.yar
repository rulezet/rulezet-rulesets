rule TTP_XOR_WriteProcessMemory_b85b {
  strings:
    $key_b85b = { ef 29 [2] dd 0b [2] db 3e [2] f5 3e [2] ca 22 }

  condition:
    any of them
}